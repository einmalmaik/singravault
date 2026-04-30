import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type {
  QuarantinedVaultItem,
  VaultIntegrityVerificationResult,
} from '@/services/vaultIntegrityService';
import type { TrustedRecoverySnapshotState } from '@/services/vaultRecoveryOrchestrator';
import {
  buildManifestEnvelopeV2FromVerifiedInputs,
  evaluateVaultIntegrityV2,
} from './decisionEngine';
import { isVaultItemEnvelopeV2 } from './itemEnvelopeCrypto';
import { deriveVaultIntegrityKeyIdV2 } from './keyId';
import { verifyVaultManifestV2 } from './manifestCrypto';
import {
  loadServerManifestEnvelopeV2,
  persistServerManifestEnvelopeV2,
} from './serverManifestStore';
import type {
  ActiveItemQuarantineReasonV2,
  ServerVaultCategoryV2,
  ServerVaultItemV2,
  TrustedLocalSnapshotMetadata,
  VaultIntegrityDecisionV2,
  VaultManifestV2,
} from './types';

type TrustedRuntimeMutationScope = {
  itemIds?: Iterable<string>;
};

export async function evaluateRuntimeVaultIntegrityV2(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  vaultKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedRecoveryState?: TrustedRecoverySnapshotState | null;
  evaluationSource: 'unlock' | 'manual_recheck' | 'sync' | 'focus_refetch';
  snapshotSource?: 'remote' | 'cache' | 'empty';
}): Promise<VaultIntegrityVerificationResult | null> {
  const vaultId = input.snapshot.vaultId;
  if (!vaultId) {
    return null;
  }

  const storedManifest = await loadServerManifestEnvelopeV2({
    userId: input.userId,
    vaultId,
  });
  if (!storedManifest) {
    return null;
  }

  const decision = await evaluateVaultIntegrityV2({
    userId: input.userId,
    vaultId,
    serverItems: toServerItems(input.snapshot.items),
    serverCategories: toServerCategories(input.snapshot.categories),
    serverManifestEnvelope: storedManifest.envelope,
    localHighWaterMark: {
      manifestRevision: storedManifest.manifestRevision,
      manifestHash: storedManifest.manifestHash,
    },
    localSnapshots: trustedRecoveryStateToV2Metadata(input.trustedRecoveryState, storedManifest),
    pendingMutations: [],
    unlockContext: {
      vaultKeyVerified: true,
      vaultKey: input.vaultKey,
      keyId: deriveVaultIntegrityKeyIdV2({ encryptedUserKey: input.encryptedUserKey }),
      protectionMode: input.snapshot.vaultProtectionMode ?? 'master_only',
    },
    evaluationSource: input.evaluationSource,
  });

  return mapDecisionToRuntimeResult(decision, input.snapshot, input.snapshotSource ?? 'remote');
}

export async function persistRuntimeManifestV2ForTrustedSnapshot(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  vaultKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedMutation?: TrustedRuntimeMutationScope;
}): Promise<'persisted' | 'skipped_legacy_items' | 'skipped_missing_vault'> {
  const vaultId = input.snapshot.vaultId;
  if (!vaultId) {
    return 'skipped_missing_vault';
  }

  if (!input.snapshot.items.every((item) => isVaultItemEnvelopeV2(item.encrypted_data))) {
    return 'skipped_legacy_items';
  }

  const keyId = deriveVaultIntegrityKeyIdV2({ encryptedUserKey: input.encryptedUserKey });
  const current = await loadServerManifestEnvelopeV2({ userId: input.userId, vaultId });
  const tombstones = await deriveTrustedDeleteTombstones({
    current,
    keyId,
    snapshot: input.snapshot,
    trustedMutation: input.trustedMutation,
    userId: input.userId,
    vaultId,
    vaultKey: input.vaultKey,
  });
  const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
    userId: input.userId,
    vaultId,
    keyId,
    keysetVersion: 1,
    manifestRevision: (current?.manifestRevision ?? 0) + 1,
    previousManifestHash: current?.manifestHash ?? undefined,
    categories: toServerCategories(input.snapshot.categories),
    items: toServerItems(input.snapshot.items),
    tombstones,
    vaultKey: input.vaultKey,
  });

  await persistServerManifestEnvelopeV2({
    userId: input.userId,
    vaultId,
    envelope: bundle.envelope,
    manifestHash: bundle.manifestHash,
    previousManifestHash: bundle.manifest.previousManifestHash ?? null,
    expectedPreviousManifestRevision: current?.manifestRevision ?? null,
    expectedPreviousManifestHash: current?.manifestHash ?? null,
  });

  return 'persisted';
}

async function deriveTrustedDeleteTombstones(input: {
  current: Awaited<ReturnType<typeof loadServerManifestEnvelopeV2>>;
  keyId: string;
  snapshot: OfflineVaultSnapshot;
  trustedMutation?: TrustedRuntimeMutationScope;
  userId: string;
  vaultId: string;
  vaultKey: CryptoKey;
}): Promise<VaultManifestV2['tombstones'] | undefined> {
  const trustedItemIds = new Set(input.trustedMutation?.itemIds ?? []);
  if (!input.current || trustedItemIds.size === 0) {
    return undefined;
  }

  const previousManifest = await verifyVaultManifestV2({
    envelope: input.current.envelope,
    key: input.vaultKey,
    expectedUserId: input.userId,
    expectedVaultId: input.vaultId,
    expectedKeyId: input.keyId,
  });
  if (!previousManifest.ok) {
    return undefined;
  }

  const snapshotItemIds = new Set(input.snapshot.items.map((item) => item.id));
  const deletedItemIds = previousManifest.manifest.items
    .map((item) => item.itemId)
    .filter((itemId) => trustedItemIds.has(itemId) && !snapshotItemIds.has(itemId));
  if (deletedItemIds.length === 0) {
    return previousManifest.manifest.tombstones;
  }

  const nextManifestRevision = input.current.manifestRevision + 1;
  const now = new Date().toISOString();
  const retainedTombstones = (previousManifest.manifest.tombstones ?? [])
    .filter((tombstone) => !deletedItemIds.includes(tombstone.itemId));

  return [
    ...retainedTombstones,
    ...deletedItemIds.map((itemId) => ({
      itemId,
      deletedAt: now,
      deletedAtManifestRevision: nextManifestRevision,
    })),
  ];
}

function mapDecisionToRuntimeResult(
  decision: VaultIntegrityDecisionV2,
  snapshot: OfflineVaultSnapshot,
  snapshotSource: 'remote' | 'cache' | 'empty',
): VaultIntegrityVerificationResult {
  const base = {
    isFirstCheck: false,
    computedRoot: 'manifest-v2',
    storedRoot: 'manifest-v2',
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
  };

  if (shouldDowngradeNonRemoteDecision(decision, snapshotSource)) {
    return {
      ...base,
      valid: false,
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    };
  }

  if (decision.mode === 'normal') {
    return {
      ...base,
      valid: true,
      computedRoot: decision.manifestHash,
      storedRoot: decision.manifestHash,
      itemCount: decision.itemCount,
      mode: 'healthy',
      quarantinedItems: [],
    };
  }

  if (decision.mode === 'item_quarantine') {
    return {
      ...base,
      valid: false,
      computedRoot: decision.manifestHash,
      storedRoot: decision.manifestHash,
      mode: 'quarantine',
      quarantinedItems: decision.quarantinedItems.map((item) => ({
        id: item.itemId,
        reason: item.reason,
        updatedAt: item.updatedAt ?? null,
      } satisfies QuarantinedVaultItem)),
    };
  }

  if (decision.mode === 'safe_mode') {
    return {
      ...base,
      valid: false,
      mode: 'blocked',
      blockedReason: decision.reason === 'category_structure_mismatch'
        ? 'category_structure_mismatch'
        : 'snapshot_malformed',
      driftedCategoryIds: decision.diagnostics
        .map((diagnostic) => diagnostic.categoryId)
        .filter((categoryId): categoryId is string => Boolean(categoryId)),
      quarantinedItems: [],
    };
  }

  return {
    ...base,
    valid: false,
    mode: decision.mode === 'sync_pending' ? 'revalidation_failed' : 'integrity_unknown',
    nonTamperReason: decision.mode === 'sync_pending'
      ? 'revalidation_failed'
      : 'snapshot_source_not_authoritative',
    quarantinedItems: [],
  };
}

function shouldDowngradeNonRemoteDecision(
  decision: VaultIntegrityDecisionV2,
  snapshotSource: 'remote' | 'cache' | 'empty',
): boolean {
  if (snapshotSource === 'remote' || decision.mode === 'normal') {
    return false;
  }

  if (decision.mode === 'item_quarantine'
    || decision.mode === 'orphan_remote'
    || decision.mode === 'missing_remote'
    || decision.mode === 'sync_pending'
    || decision.mode === 'conflict') {
    return true;
  }

  return decision.mode === 'safe_mode'
    && (decision.reason === 'category_structure_mismatch' || decision.reason === 'vault_structure_corrupt');
}

function toServerItems(items: OfflineVaultSnapshot['items']): ServerVaultItemV2[] {
  return items.map((item) => ({
    id: item.id,
    user_id: item.user_id,
    vault_id: item.vault_id,
    encrypted_data: item.encrypted_data,
    item_type: item.item_type,
    updated_at: item.updated_at,
  }));
}

function toServerCategories(categories: OfflineVaultSnapshot['categories']): ServerVaultCategoryV2[] {
  return categories.map((category) => ({
    id: category.id,
    user_id: category.user_id,
    name: category.name,
    icon: category.icon,
    color: category.color,
    parent_id: category.parent_id,
    sort_order: category.sort_order,
    updated_at: category.updated_at,
  }));
}

function trustedRecoveryStateToV2Metadata(
  state: TrustedRecoverySnapshotState | null | undefined,
  manifest: { userId: string; vaultId: string; manifestHash: string; manifestRevision: number },
): TrustedLocalSnapshotMetadata[] {
  if (!state?.trustedSnapshot) {
    return [];
  }

  return [{
    snapshotVersion: 2,
    snapshotId: `trusted:${manifest.userId}:${manifest.vaultId}`,
    userId: manifest.userId,
    vaultId: manifest.vaultId,
    manifestHash: manifest.manifestHash,
    manifestRevision: manifest.manifestRevision,
    createdAt: state.trustedSnapshot.updatedAt,
    itemCount: state.trustedSnapshot.items.length,
    categoryCount: state.trustedSnapshot.categories.length,
    recoverableItemIds: state.trustedSnapshot.items.map((item) => item.id),
  }];
}

export function isActiveQuarantineReasonV2(reason: string): reason is ActiveItemQuarantineReasonV2 {
  return new Set<string>([
    'ciphertext_changed',
    'aead_auth_failed',
    'item_envelope_malformed',
    'item_aad_mismatch',
    'item_manifest_hash_mismatch',
    'item_revision_replay',
    'item_key_id_mismatch',
    'duplicate_active_item_record',
  ]).has(reason);
}
