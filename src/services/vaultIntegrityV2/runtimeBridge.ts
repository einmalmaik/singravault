import { isLikelyOfflineError, type OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  computeVaultSnapshotDigest,
  type VaultIntegritySnapshot,
} from '@/services/vaultIntegrityService';
import type {
  QuarantinedVaultItem,
  VaultIntegrityNonTamperMode,
  VaultIntegrityNonTamperReason,
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
  loadManifestHighWaterMark,
  saveManifestHighWaterMark,
  type ManifestHighWaterMarkRecordV1,
} from './manifestHighWaterMarkStore';
import {
  loadManifestPersistRetryRecord,
  removeManifestPersistRetryRecord,
  saveManifestPersistRetryRecord,
} from './manifestPersistRetryStore';
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

  const snapshotSource = input.snapshotSource ?? 'remote';
  let storedManifest: Awaited<ReturnType<typeof loadServerManifestEnvelopeV2>>;
  try {
    storedManifest = await loadServerManifestEnvelopeV2({
      userId: input.userId,
      vaultId,
    });
  } catch (error) {
    if (snapshotSource !== 'remote' && isLikelyOfflineError(error)) {
      return null;
    }
    throw error;
  }
  if (!storedManifest) {
    return null;
  }

  let localHighWaterMark: ManifestHighWaterMarkRecordV1 | null;
  try {
    localHighWaterMark = await loadManifestHighWaterMark(input.userId, vaultId);
  } catch {
    return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'rollback_check_unavailable');
  }

  const keyId = deriveVaultIntegrityKeyIdV2({ encryptedUserKey: input.encryptedUserKey });
  if (
    !localHighWaterMark
    && await trustedSnapshotConflictsWithServerManifest({
      userId: input.userId,
      vaultId,
      keyId,
      storedManifest,
      snapshotState: input.trustedRecoveryState,
      vaultKey: input.vaultKey,
    })
  ) {
    return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'manifest_snapshot_conflict');
  }

  const decision = await evaluateVaultIntegrityV2({
    userId: input.userId,
    vaultId,
    serverItems: toServerItems(input.snapshot.items),
    serverCategories: toServerCategories(input.snapshot.categories),
    serverManifestEnvelope: storedManifest.envelope,
    localHighWaterMark: localHighWaterMark
      ? {
        manifestRevision: localHighWaterMark.manifestRevision,
        manifestHash: localHighWaterMark.manifestHash,
      }
      : undefined,
    localSnapshots: trustedRecoveryStateToV2Metadata(input.trustedRecoveryState, {
      userId: input.userId,
      vaultId,
      highWaterMark: localHighWaterMark,
    }),
    pendingMutations: [],
    unlockContext: {
      vaultKeyVerified: true,
      vaultKey: input.vaultKey,
      keyId,
      protectionMode: input.snapshot.vaultProtectionMode ?? 'master_only',
    },
    evaluationSource: input.evaluationSource,
  });

  if (
    canAdvanceManifestHighWaterMark(decision)
    && !shouldDowngradeNonRemoteDecision(decision, snapshotSource)
  ) {
    try {
      await saveManifestHighWaterMark({
        userId: input.userId,
        vaultId,
        manifestRevision: decision.manifestRevision,
        manifestHash: decision.manifestHash,
        keyId,
      });
    } catch {
      return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'rollback_check_unavailable');
    }
  }

  if (canRetryRuntimeManifestPersistAfterDecision({
    decisionMode: decision.mode,
    snapshotSource,
  })) {
    const retryResult = await retryPendingRuntimeManifestV2ForSnapshot({
      userId: input.userId,
      snapshot: input.snapshot,
      vaultKey: input.vaultKey,
      encryptedUserKey: input.encryptedUserKey,
    });
    if (retryResult.status === 'failed') {
      return buildRuntimeNonTamperResult(input.snapshot, 'revalidation_failed', 'manifest_persist_failed');
    }
    if (retryResult.status === 'store_unavailable') {
      return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'rollback_check_unavailable');
    }
    if (retryResult.status === 'snapshot_digest_unavailable') {
      return buildRuntimeNonTamperResult(input.snapshot, 'revalidation_failed', 'manifest_persist_failed');
    }
    if (retryResult.status === 'snapshot_mismatch') {
      try {
        await removeManifestPersistRetryRecord(input.userId, vaultId);
      } catch {
        return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'rollback_check_unavailable');
      }
    }
    if (retryResult.status === 'persisted' && decision.mode === 'orphan_remote') {
      const reloadedManifest = await loadServerManifestEnvelopeV2({ userId: input.userId, vaultId });
      if (reloadedManifest) {
        const revalidatedDecision = await evaluateVaultIntegrityV2({
          userId: input.userId,
          vaultId,
          serverItems: toServerItems(input.snapshot.items),
          serverCategories: toServerCategories(input.snapshot.categories),
          serverManifestEnvelope: reloadedManifest.envelope,
          localHighWaterMark: localHighWaterMark
            ? {
              manifestRevision: localHighWaterMark.manifestRevision,
              manifestHash: localHighWaterMark.manifestHash,
            }
            : undefined,
          localSnapshots: trustedRecoveryStateToV2Metadata(input.trustedRecoveryState, {
            userId: input.userId,
            vaultId,
            highWaterMark: localHighWaterMark,
          }),
          pendingMutations: [],
          unlockContext: {
            vaultKeyVerified: true,
            vaultKey: input.vaultKey,
            keyId,
            protectionMode: input.snapshot.vaultProtectionMode ?? 'master_only',
          },
          evaluationSource: input.evaluationSource,
        });
        if (
          canAdvanceManifestHighWaterMark(revalidatedDecision)
          && !shouldDowngradeNonRemoteDecision(revalidatedDecision, snapshotSource)
        ) {
          try {
            await saveManifestHighWaterMark({
              userId: input.userId,
              vaultId,
              manifestRevision: revalidatedDecision.manifestRevision,
              manifestHash: revalidatedDecision.manifestHash,
              keyId,
            });
          } catch {
            return buildRuntimeNonTamperResult(input.snapshot, 'integrity_unknown', 'rollback_check_unavailable');
          }
        }
        return mapDecisionToRuntimeResult(revalidatedDecision, input.snapshot, snapshotSource);
      }
    }
  }

  return mapDecisionToRuntimeResult(decision, input.snapshot, snapshotSource);
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
  await saveManifestHighWaterMark({
    userId: input.userId,
    vaultId,
    manifestRevision: bundle.manifest.manifestRevision,
    manifestHash: bundle.manifestHash,
    keyId,
  });

  return 'persisted';
}

export async function retryPendingRuntimeManifestV2ForSnapshot(input: {
  userId: string;
  snapshot: OfflineVaultSnapshot;
  vaultKey: CryptoKey;
  encryptedUserKey?: string | null;
  trustedMutation?: TrustedRuntimeMutationScope;
  snapshotDigest?: string | null;
}): Promise<{
  status:
    | 'no_pending'
    | 'persisted'
    | 'skipped_legacy_items'
    | 'skipped_missing_vault'
    | 'failed'
    | 'store_unavailable'
    | 'snapshot_digest_unavailable'
    | 'snapshot_mismatch';
  errorCode?: string;
}> {
  const vaultId = input.snapshot.vaultId;
  if (!vaultId) {
    return { status: 'skipped_missing_vault' };
  }

  let pendingSnapshotDigest: string;
  try {
    const pending = await loadManifestPersistRetryRecord(input.userId, vaultId);
    if (!pending) {
      return { status: 'no_pending' };
    }
    pendingSnapshotDigest = pending.snapshotDigest;
  } catch {
    return { status: 'store_unavailable' };
  }

  const currentSnapshotDigest = await resolveRetrySnapshotDigest(input);
  if (!currentSnapshotDigest) {
    return { status: 'snapshot_digest_unavailable', errorCode: 'manifest_retry_snapshot_digest_unavailable' };
  }

  if (currentSnapshotDigest !== pendingSnapshotDigest) {
    return { status: 'snapshot_mismatch', errorCode: 'manifest_retry_snapshot_mismatch' };
  }

  try {
    const status = await persistRuntimeManifestV2ForTrustedSnapshot(input);
    await removeManifestPersistRetryRecord(input.userId, vaultId);
    return { status };
  } catch (error) {
    const errorCode = safeManifestPersistErrorCode(error);
    try {
      await saveManifestPersistRetryRecord({
        userId: input.userId,
        vaultId,
        snapshotDigest: pendingSnapshotDigest,
        lastErrorCode: errorCode,
      });
    } catch {
      return { status: 'store_unavailable', errorCode };
    }
    return { status: 'failed', errorCode };
  }
}

async function resolveRetrySnapshotDigest(input: {
  snapshot: OfflineVaultSnapshot;
  snapshotDigest?: string | null;
}): Promise<string | null> {
  if (input.snapshotDigest !== undefined) {
    return input.snapshotDigest;
  }

  try {
    return await computeVaultSnapshotDigest(toIntegritySnapshot(input.snapshot));
  } catch {
    return null;
  }
}

function toIntegritySnapshot(snapshot: OfflineVaultSnapshot): VaultIntegritySnapshot {
  return {
    items: snapshot.items,
    categories: snapshot.categories,
  };
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
      blockedReason: decision.reason === 'manifest_rollback_detected'
        ? 'manifest_rollback_detected'
        : decision.reason === 'category_structure_mismatch'
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

function canAdvanceManifestHighWaterMark(decision: VaultIntegrityDecisionV2): decision is Extract<
  VaultIntegrityDecisionV2,
  { mode: 'normal' | 'item_quarantine' }
> {
  return decision.mode === 'normal' || decision.mode === 'item_quarantine';
}

function canRetryRuntimeManifestPersistAfterDecision(input: {
  decisionMode: VaultIntegrityDecisionV2['mode'];
  snapshotSource: 'remote' | 'cache' | 'empty';
}): boolean {
  return (input.decisionMode === 'normal' || input.decisionMode === 'orphan_remote')
    && input.snapshotSource === 'remote';
}

function buildRuntimeNonTamperResult(
  snapshot: OfflineVaultSnapshot,
  mode: VaultIntegrityNonTamperMode,
  reason: VaultIntegrityNonTamperReason,
): VaultIntegrityVerificationResult {
  return {
    valid: false,
    isFirstCheck: false,
    computedRoot: 'manifest-v2',
    storedRoot: 'manifest-v2',
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    mode,
    nonTamperReason: reason,
    quarantinedItems: [],
  };
}

async function trustedSnapshotConflictsWithServerManifest(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  storedManifest: Awaited<ReturnType<typeof loadServerManifestEnvelopeV2>>;
  snapshotState?: TrustedRecoverySnapshotState | null;
  vaultKey: CryptoKey;
}): Promise<boolean> {
  const trustedSnapshot = input.snapshotState?.trustedSnapshot;
  if (!trustedSnapshot || !input.storedManifest) {
    return false;
  }

  if (trustedSnapshot.userId !== input.userId || trustedSnapshot.vaultId !== input.vaultId) {
    return true;
  }

  const decision = await evaluateVaultIntegrityV2({
    userId: input.userId,
    vaultId: input.vaultId,
    serverItems: toServerItems(trustedSnapshot.items),
    serverCategories: toServerCategories(trustedSnapshot.categories),
    serverManifestEnvelope: input.storedManifest.envelope,
    localHighWaterMark: undefined,
    localSnapshots: [],
    pendingMutations: [],
    unlockContext: {
      vaultKeyVerified: true,
      vaultKey: input.vaultKey,
      keyId: input.keyId,
      protectionMode: trustedSnapshot.vaultProtectionMode ?? 'master_only',
    },
    evaluationSource: 'manual_recheck',
  });

  return decision.mode !== 'normal';
}

export function safeManifestPersistErrorCode(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = String((error as { code?: unknown }).code ?? '');
    if (code) {
      return sanitizeErrorCode(code);
    }
  }

  const message = error instanceof Error ? error.message.toLowerCase() : '';
  if (message.includes('conflict') || message.includes('revision') || message.includes('hash')) {
    return 'manifest_write_conflict';
  }
  if (message.includes('network') || message.includes('fetch') || message.includes('timeout')) {
    return 'network_unavailable';
  }
  if (message.includes('indexeddb') || message.includes('high-water mark')) {
    return 'local_integrity_store_unavailable';
  }
  return 'manifest_persist_failed';
}

function sanitizeErrorCode(code: string): string {
  return code.toLowerCase().replace(/[^a-z0-9_:-]/g, '_').slice(0, 80) || 'manifest_persist_failed';
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
  input: {
    userId: string;
    vaultId: string;
    highWaterMark: Pick<ManifestHighWaterMarkRecordV1, 'manifestHash' | 'manifestRevision'> | null;
  },
): TrustedLocalSnapshotMetadata[] {
  if (!state?.trustedSnapshot) {
    return [];
  }

  if (
    state.trustedSnapshot.userId !== input.userId
    || state.trustedSnapshot.vaultId !== input.vaultId
  ) {
    return [];
  }

  return [{
    snapshotVersion: 2,
    snapshotId: 'trusted_recovery_snapshot',
    userId: input.userId,
    vaultId: input.vaultId,
    manifestHash: input.highWaterMark?.manifestHash ?? 'local-trusted-snapshot-unanchored',
    manifestRevision: input.highWaterMark?.manifestRevision ?? 0,
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
