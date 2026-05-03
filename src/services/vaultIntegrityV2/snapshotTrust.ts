import type {
  TrustedLocalSnapshotMetadata,
  VaultIntegrityDecisionV2,
  VaultManifestV2,
} from './types';

export interface TrustedLocalSnapshotV2 extends TrustedLocalSnapshotMetadata {
  deviceId: string;
  encryptedSnapshotPayload: string;
  integrityTag: string;
}

export function canCreateTrustedSnapshotV2(decision: VaultIntegrityDecisionV2): boolean {
  return decision.mode === 'normal';
}

export function buildTrustedLocalSnapshotMetadataV2(input: {
  decision: VaultIntegrityDecisionV2;
  manifest: VaultManifestV2;
  manifestHash: string;
  snapshotId: string;
  deviceId: string;
  encryptedSnapshotPayload: string;
  integrityTag: string;
}): TrustedLocalSnapshotV2 {
  if (!canCreateTrustedSnapshotV2(input.decision)) {
    throw new Error('Trusted snapshots can only be created after a normal Manifest V2 verification.');
  }

  return {
    snapshotVersion: 2,
    snapshotId: input.snapshotId,
    userId: input.manifest.userId,
    vaultId: input.manifest.vaultId,
    deviceId: input.deviceId,
    manifestHash: input.manifestHash,
    manifestRevision: input.manifest.manifestRevision,
    createdAt: new Date().toISOString(),
    itemCount: input.manifest.items.filter((item) => !item.deleted).length,
    categoryCount: 0,
    recoverableItemIds: input.manifest.items
      .filter((item) => !item.deleted)
      .map((item) => item.itemId)
      .sort((left, right) => left.localeCompare(right)),
    encryptedSnapshotPayload: input.encryptedSnapshotPayload,
    integrityTag: input.integrityTag,
  };
}

export function canRestoreFromTrustedSnapshotV2(input: {
  itemId: string;
  reason: string;
  snapshot?: TrustedLocalSnapshotMetadata | null;
  userId: string;
  vaultId: string;
}): boolean {
  if (!input.snapshot) {
    return false;
  }

  if (input.snapshot.userId !== input.userId || input.snapshot.vaultId !== input.vaultId) {
    return false;
  }

  if (!input.snapshot.recoverableItemIds?.includes(input.itemId)) {
    return false;
  }

  return new Set([
    'ciphertext_changed',
    'aead_auth_failed',
    'item_manifest_hash_mismatch',
    'item_aad_mismatch',
    'item_envelope_malformed',
  ]).has(input.reason);
}
