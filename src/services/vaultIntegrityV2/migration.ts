import {
  buildManifestEnvelopeV2FromVerifiedInputs,
} from './decisionEngine';
import { evaluateVaultIntegrityV2 } from './decisionEngine';
import { isVaultItemEnvelopeV2 } from './itemEnvelopeCrypto';
import type {
  IntegrityDiagnostic,
  ServerVaultCategoryV2,
  ServerVaultItemV2,
  TrustedLocalSnapshotMetadata,
  VaultIntegrityMigrationResult,
  VaultManifestEnvelopeV2,
} from './types';

export async function migrateVaultIntegrityToV2(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  keysetVersion?: number;
  vaultKeyVerified: boolean;
  vaultKey?: CryptoKey;
  serverItems: ServerVaultItemV2[];
  serverCategories: ServerVaultCategoryV2[];
  existingManifestEnvelope?: VaultManifestEnvelopeV2 | string;
  localSnapshots?: TrustedLocalSnapshotMetadata[];
  oldQuarantineRecords?: Array<{ id?: string; itemId?: string; reason: string }>;
  manifestRevision?: number;
}): Promise<VaultIntegrityMigrationResult> {
  if (!input.vaultKeyVerified || !input.vaultKey) {
    return blocked('vault_key_not_verified', 'Migration requires a verified vault key.');
  }

  if (input.existingManifestEnvelope) {
    const decision = await evaluateVaultIntegrityV2({
      userId: input.userId,
      vaultId: input.vaultId,
      serverItems: input.serverItems,
      serverCategories: input.serverCategories,
      serverManifestEnvelope: input.existingManifestEnvelope,
      localSnapshots: input.localSnapshots ?? [],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: input.vaultKey,
        keyId: input.keyId,
        protectionMode: 'master_only',
      },
      evaluationSource: 'migration',
    });

    if (decision.mode === 'normal') {
      return {
        status: 'already_migrated',
        manifestRevision: decision.manifestRevision,
      };
    }

    if (decision.mode === 'safe_mode') {
      return {
        status: 'requires_safe_mode',
        reason: decision.reason,
        diagnostics: decision.diagnostics,
      };
    }

    if (decision.mode === 'item_quarantine') {
      return blocked('active_quarantine_present', 'Existing Manifest V2 state has active quarantine.', decision.diagnostics);
    }
  }

  const activeLegacyRecords = (input.oldQuarantineRecords ?? []).filter((record) => (
    record.reason === 'ciphertext_changed'
    || record.reason === 'aead_auth_failed'
    || record.reason === 'item_manifest_hash_mismatch'
    || record.reason === 'item_aad_mismatch'
  ));
  if (activeLegacyRecords.length > 0) {
    return blocked('active_quarantine_present', 'Active legacy quarantine records must be resolved before V2 migration.', activeLegacyRecords.map((record) => ({
      code: 'migration_blocked',
      itemId: record.itemId ?? record.id,
      message: 'Active legacy quarantine record blocks V2 migration.',
    })));
  }

  const legacyItems = input.serverItems.filter((item) => !isVaultItemEnvelopeV2(item.encrypted_data));
  if (legacyItems.length > 0) {
    return blocked('legacy_items_require_reencrypt', 'Legacy item envelopes must be re-encrypted with Item-AAD V2 before manifest migration.', legacyItems.map((item) => ({
      code: 'legacy_item_requires_migration',
      itemId: item.id,
      message: 'Item is not stored as an Item-Envelope V2.',
    })));
  }

  const duplicateIds = findDuplicateItemIds(input.serverItems);
  if (duplicateIds.length > 0) {
    return {
      status: 'requires_safe_mode',
      reason: 'vault_structure_corrupt',
      diagnostics: duplicateIds.map((itemId) => ({
        code: 'duplicate_active_item_record',
        itemId,
        message: 'Duplicate item records make migration ambiguous.',
      })),
    };
  }

  const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
    userId: input.userId,
    vaultId: input.vaultId,
    keyId: input.keyId,
    keysetVersion: input.keysetVersion ?? 1,
    manifestRevision: input.manifestRevision ?? 1,
    categories: input.serverCategories,
    items: input.serverItems,
    vaultKey: input.vaultKey,
  });

  return {
    status: 'migrated',
    manifestRevision: bundle.manifest.manifestRevision,
    migratedItemCount: bundle.manifest.items.length,
    manifest: bundle.manifest,
  };
}

function blocked(
  reason: Exclude<VaultIntegrityMigrationResult, { status: 'migrated' | 'already_migrated' | 'requires_safe_mode' }>['reason'],
  message: string,
  diagnostics: IntegrityDiagnostic[] = [],
): VaultIntegrityMigrationResult {
  return {
    status: 'blocked',
    reason,
    diagnostics: diagnostics.length > 0 ? diagnostics : [{ code: 'migration_blocked', message }],
  };
}

function findDuplicateItemIds(items: ServerVaultItemV2[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const item of items) {
    if (seen.has(item.id)) {
      duplicates.add(item.id);
    }
    seen.add(item.id);
  }
  return [...duplicates].sort((left, right) => left.localeCompare(right));
}
