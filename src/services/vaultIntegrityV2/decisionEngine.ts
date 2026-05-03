import { computeCategoriesHashV2, verifyCategoriesAgainstManifestV2 } from './categoryIntegrity';
import {
  detectManifestRollback,
  encryptVaultManifestV2,
  hashVaultManifestV2,
  verifyVaultManifestV2,
} from './manifestCrypto';
import {
  hashVaultItemEnvelopeV2,
  isVaultItemEnvelopeV2,
  parseVaultItemEnvelopeV2,
  verifyAndDecryptItemEnvelopeV2,
} from './itemEnvelopeCrypto';
import type {
  ActiveItemQuarantineReasonV2,
  IntegrityDiagnostic,
  IntegrityEvaluationInputV2,
  MissingRemoteItemDecision,
  OrphanRemoteItemDecision,
  QuarantinedItemDecisionV2,
  ServerVaultCategoryV2,
  ServerVaultItemV2,
  VaultIntegrityDecisionV2,
  VaultManifestEnvelopeV2,
  VaultManifestV2,
} from './types';

export async function evaluateVaultIntegrityV2(
  input: IntegrityEvaluationInputV2,
): Promise<VaultIntegrityDecisionV2> {
  if (!input.unlockContext.vaultKeyVerified) {
    return {
      mode: 'revalidation_failed',
      reason: 'vault_key_not_verified',
      diagnostics: [{ code: 'vault_key_not_verified', message: 'Vault key was not verified before integrity evaluation.' }],
    };
  }

  if (input.unlockContext.deviceKeyStateStale) {
    return {
      mode: 'revalidation_failed',
      reason: 'device_key_state_stale',
      diagnostics: [{ code: 'device_key_state_stale', message: 'Device-Key state is stale and cannot prove item tampering.' }],
    };
  }

  if (input.pendingMutations.length > 0) {
    return {
      mode: 'sync_pending',
      pendingMutations: input.pendingMutations,
      diagnostics: [{ code: 'sync_pending', message: 'Pending local mutations must settle before quarantine decisions are persisted.' }],
    };
  }

  const manifestResult = await verifyVaultManifestV2({
    envelope: input.serverManifestEnvelope,
    key: input.unlockContext.vaultKey,
    expectedUserId: input.userId,
    expectedVaultId: input.vaultId,
    expectedKeyId: input.unlockContext.keyId,
  });
  if (manifestResult.ok === false) {
    return {
      mode: 'safe_mode',
      reason: manifestResult.reason,
      diagnostics: manifestResult.diagnostics,
    };
  }

  const rollbackResult = detectManifestRollback(
    manifestResult.manifest,
    manifestResult.manifestHash,
    input.localHighWaterMark,
  );
  if (!rollbackResult.ok) {
    return {
      mode: 'safe_mode',
      reason: 'manifest_rollback_detected',
      diagnostics: rollbackResult.diagnostics,
    };
  }

  const categoryResult = await verifyCategoriesAgainstManifestV2(
    input.serverCategories,
    manifestResult.manifest,
  );
  if (!categoryResult.ok) {
    return {
      mode: 'safe_mode',
      reason: 'category_structure_mismatch',
      diagnostics: categoryResult.diagnostics,
    };
  }

  return evaluateItemsAgainstManifestV2({
    serverItems: input.serverItems,
    manifest: manifestResult.manifest,
    manifestHash: manifestResult.manifestHash,
    vaultKey: input.unlockContext.vaultKey,
    localSnapshots: input.localSnapshots,
  });
}

export async function evaluateItemsAgainstManifestV2(input: {
  serverItems: ServerVaultItemV2[];
  manifest: VaultManifestV2;
  manifestHash: string;
  vaultKey?: CryptoKey;
  localSnapshots: IntegrityEvaluationInputV2['localSnapshots'];
}): Promise<VaultIntegrityDecisionV2> {
  const diagnostics: IntegrityDiagnostic[] = [];
  const quarantinedItems: QuarantinedItemDecisionV2[] = [];
  const orphanItems: OrphanRemoteItemDecision[] = [];
  const missingItems: MissingRemoteItemDecision[] = [];
  const healthyItemIds: string[] = [];
  const manifestItems = input.manifest.items.filter((item) => !item.deleted);
  const manifestById = new Map(manifestItems.map((item) => [item.itemId, item]));
  const serverItemsById = new Map<string, ServerVaultItemV2>();
  const duplicateIds = new Set<string>();

  for (const item of input.serverItems) {
    if (serverItemsById.has(item.id)) {
      duplicateIds.add(item.id);
    }
    serverItemsById.set(item.id, item);
  }

  for (const duplicateId of duplicateIds) {
    diagnostics.push({
      code: 'duplicate_active_item_record',
      itemId: duplicateId,
      manifestRevision: input.manifest.manifestRevision,
      message: 'More than one active server record exists for the same item id.',
    });
    quarantinedItems.push(buildQuarantineDecision({
      itemId: duplicateId,
      reason: 'duplicate_active_item_record',
      manifestRevision: input.manifest.manifestRevision,
    }));
  }

  for (const item of input.serverItems) {
    if (duplicateIds.has(item.id)) {
      continue;
    }

    const expected = manifestById.get(item.id);
    if (!expected) {
      const observedEnvelopeHash = isVaultItemEnvelopeV2(item.encrypted_data)
        ? await hashVaultItemEnvelopeV2(item.encrypted_data)
        : undefined;
      orphanItems.push({
        itemId: item.id,
        reason: 'orphan_remote',
        observedEnvelopeHash,
        updatedAt: item.updated_at ?? null,
      });
      diagnostics.push({
        code: 'orphan_remote',
        itemId: item.id,
        message: 'Server item is not part of the authenticated manifest.',
        observedHashPrefix: observedEnvelopeHash?.slice(0, 12),
      });
      continue;
    }

    const observedEnvelopeHash = await hashVaultItemEnvelopeV2(item.encrypted_data);
    if (observedEnvelopeHash !== expected.envelopeHash) {
      diagnostics.push({
        code: 'item_manifest_hash_mismatch',
        itemId: item.id,
        manifestRevision: input.manifest.manifestRevision,
        message: 'Server item envelope hash does not match the authenticated manifest.',
        observedHashPrefix: observedEnvelopeHash.slice(0, 12),
      });
      quarantinedItems.push(buildQuarantineDecision({
        itemId: item.id,
        reason: 'item_manifest_hash_mismatch',
        manifestRevision: input.manifest.manifestRevision,
        observedEnvelopeHash,
        expectedEnvelopeHash: expected.envelopeHash,
        updatedAt: item.updated_at ?? null,
        recoverable: hasTrustedSnapshotItem(input.localSnapshots, item.id),
      }));
      continue;
    }

    const itemResult = await verifyItemAgainstManifestEntry({
      item,
      manifest: input.manifest,
      key: input.vaultKey,
      expected,
      observedEnvelopeHash,
    });
    if (itemResult.ok === false) {
      diagnostics.push(...itemResult.diagnostics);
      quarantinedItems.push(buildQuarantineDecision({
        itemId: item.id,
        reason: itemResult.reason,
        manifestRevision: input.manifest.manifestRevision,
        observedEnvelopeHash,
        expectedEnvelopeHash: expected.envelopeHash,
        updatedAt: item.updated_at ?? null,
        recoverable: hasTrustedSnapshotItem(input.localSnapshots, item.id),
      }));
      continue;
    }

    healthyItemIds.push(item.id);
  }

  for (const manifestItem of manifestItems) {
    if (serverItemsById.has(manifestItem.itemId)) {
      continue;
    }

    const recoverable = hasTrustedSnapshotItem(input.localSnapshots, manifestItem.itemId);
    missingItems.push({
      itemId: manifestItem.itemId,
      reason: 'missing_on_server',
      recoverable,
    });
    diagnostics.push({
      code: 'missing_on_server',
      itemId: manifestItem.itemId,
      manifestRevision: input.manifest.manifestRevision,
      message: recoverable
        ? 'Manifest item is missing remotely but recoverable from a trusted snapshot.'
        : 'Manifest item is missing remotely and no trusted snapshot copy is available.',
    });
  }

  healthyItemIds.sort((left, right) => left.localeCompare(right));

  if (quarantinedItems.length > 0) {
    return {
      mode: 'item_quarantine',
      manifestRevision: input.manifest.manifestRevision,
      manifestHash: input.manifestHash,
      quarantinedItems: dedupeQuarantineDecisions(quarantinedItems),
      healthyItemIds,
      diagnostics,
    };
  }

  if (missingItems.length > 0) {
    return {
      mode: 'missing_remote',
      manifestRevision: input.manifest.manifestRevision,
      manifestHash: input.manifestHash,
      missingItems,
      healthyItemIds,
      diagnostics,
    };
  }

  if (orphanItems.length > 0) {
    return {
      mode: 'orphan_remote',
      manifestRevision: input.manifest.manifestRevision,
      manifestHash: input.manifestHash,
      orphanItems,
      healthyItemIds,
      diagnostics,
    };
  }

  return {
    mode: 'normal',
    manifestRevision: input.manifest.manifestRevision,
    manifestHash: input.manifestHash,
    itemCount: healthyItemIds.length,
    healthyItemIds,
    diagnostics,
  };
}

export async function buildManifestV2FromVerifiedInputs(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  keysetVersion: number;
  manifestRevision: number;
  previousManifestHash?: string;
  categories: ServerVaultCategoryV2[];
  items: ServerVaultItemV2[];
  tombstones?: VaultManifestV2['tombstones'];
  createdAt?: string;
  createdByDeviceId?: string;
}): Promise<VaultManifestV2> {
  const categoriesHash = await computeCategoriesHashV2(input.categories);
  const items = await Promise.all(input.items.map(async (item) => {
    const parsed = parseVaultItemEnvelopeV2(item.encrypted_data);
    const fallbackItemType = item.item_type ?? 'password';
    return {
      itemId: item.id,
      itemType: parsed.ok ? parsed.envelope.itemType : fallbackItemType,
      itemRevision: parsed.ok ? parsed.envelope.itemRevision : 1,
      envelopeVersion: 2 as const,
      keyId: parsed.ok ? parsed.envelope.keyId : input.keyId,
      envelopeHash: await hashVaultItemEnvelopeV2(item.encrypted_data),
    };
  }));

  return {
    manifestVersion: 2,
    vaultId: input.vaultId,
    userId: input.userId,
    keysetVersion: input.keysetVersion,
    manifestRevision: input.manifestRevision,
    previousManifestHash: input.previousManifestHash,
    createdByDeviceId: input.createdByDeviceId,
    createdAt: input.createdAt ?? new Date().toISOString(),
    categoriesHash,
    items: items.sort((left, right) => left.itemId.localeCompare(right.itemId)),
    tombstones: input.tombstones?.length
      ? [...input.tombstones].sort((left, right) => left.itemId.localeCompare(right.itemId))
      : undefined,
  };
}

export async function buildManifestEnvelopeV2FromVerifiedInputs(input: {
  userId: string;
  vaultId: string;
  keyId: string;
  keysetVersion: number;
  manifestRevision: number;
  previousManifestHash?: string;
  categories: ServerVaultCategoryV2[];
  items: ServerVaultItemV2[];
  tombstones?: VaultManifestV2['tombstones'];
  vaultKey: CryptoKey;
  createdAt?: string;
  createdByDeviceId?: string;
}): Promise<{ manifest: VaultManifestV2; manifestHash: string; envelope: VaultManifestEnvelopeV2 }> {
  const manifest = await buildManifestV2FromVerifiedInputs(input);
  const manifestHash = await hashVaultManifestV2(manifest);
  const envelope = await encryptVaultManifestV2(manifest, input.vaultKey, input.keyId);
  return { manifest, manifestHash, envelope };
}

async function verifyItemAgainstManifestEntry(input: {
  item: ServerVaultItemV2;
  manifest: VaultManifestV2;
  key?: CryptoKey;
  expected: VaultManifestV2['items'][number];
  observedEnvelopeHash: string;
}): Promise<{ ok: true } | { ok: false; reason: ActiveItemQuarantineReasonV2; diagnostics: IntegrityDiagnostic[] }> {
  if (!input.key) {
    return {
      ok: false,
      reason: 'aead_auth_failed',
      diagnostics: [{
        code: 'aead_auth_failed',
        itemId: input.item.id,
        message: 'Vault key is required to authenticate an item envelope.',
      }],
    };
  }

  const result = await verifyAndDecryptItemEnvelopeV2(input.item.encrypted_data, input.key, {
    vaultId: input.manifest.vaultId,
    userId: input.manifest.userId,
    itemId: input.expected.itemId,
    itemType: input.expected.itemType,
    keyId: input.expected.keyId,
    itemRevision: input.expected.itemRevision,
    schemaVersion: 1,
  });
  if (result.ok === true) {
    return { ok: true };
  }

  return { ok: false, reason: result.reason, diagnostics: result.diagnostics };
}

function hasTrustedSnapshotItem(
  snapshots: IntegrityEvaluationInputV2['localSnapshots'],
  itemId: string,
): boolean {
  return snapshots.some((snapshot) => snapshot.recoverableItemIds?.includes(itemId));
}

function buildQuarantineDecision(input: {
  itemId: string;
  reason: ActiveItemQuarantineReasonV2;
  manifestRevision: number;
  observedEnvelopeHash?: string;
  expectedEnvelopeHash?: string;
  updatedAt?: string | null;
  recoverable?: boolean;
}): QuarantinedItemDecisionV2 {
  return {
    itemId: input.itemId,
    reason: input.reason,
    manifestRevision: input.manifestRevision,
    observedEnvelopeHash: input.observedEnvelopeHash,
    expectedEnvelopeHash: input.expectedEnvelopeHash,
    updatedAt: input.updatedAt ?? null,
    recoverable: input.recoverable ?? false,
  };
}

function dedupeQuarantineDecisions(items: QuarantinedItemDecisionV2[]): QuarantinedItemDecisionV2[] {
  const byIdentity = new Map<string, QuarantinedItemDecisionV2>();
  for (const item of items) {
    const identity = [
      item.itemId,
      item.reason,
      item.observedEnvelopeHash ?? '',
      item.manifestRevision,
    ].join(':');
    byIdentity.set(identity, item);
  }

  return [...byIdentity.values()].sort((left, right) => {
    return left.itemId.localeCompare(right.itemId)
      || left.reason.localeCompare(right.reason);
  });
}
