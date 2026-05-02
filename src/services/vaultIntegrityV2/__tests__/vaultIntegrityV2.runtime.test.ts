import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  buildManifestEnvelopeV2FromVerifiedInputs,
  encryptItemEnvelopeV2,
  evaluateRuntimeVaultIntegrityV2,
  loadManifestHighWaterMark,
  loadManifestPersistRetryRecord,
  persistRuntimeManifestV2ForTrustedSnapshot,
  removeManifestHighWaterMark,
  removeManifestPersistRetryRecord,
  retryPendingRuntimeManifestV2ForSnapshot,
  saveManifestPersistRetryRecord,
  saveManifestHighWaterMark,
  verifyVaultManifestV2,
  type ServerVaultCategoryV2,
  type ServerVaultItemV2,
} from '../index';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import { computeVaultSnapshotDigest } from '@/services/vaultIntegrityService';

const USER_ID = 'user-runtime';
const VAULT_ID = 'vault-runtime';
const KEY_ID = 'legacy-kdf-v1';

const manifestStore = vi.hoisted(() => ({
  loadServerManifestEnvelopeV2: vi.fn(),
  persistServerManifestEnvelopeV2: vi.fn(),
}));

vi.mock('../serverManifestStore', () => manifestStore);

async function testKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function category(): ServerVaultCategoryV2 {
  return {
    id: 'cat-1',
    user_id: USER_ID,
    name: 'enc:category',
    icon: null,
    color: null,
    parent_id: null,
    sort_order: null,
    updated_at: '2026-04-30T10:00:00.000Z',
  };
}

async function item(key: CryptoKey, id: string): Promise<ServerVaultItemV2> {
  return {
    id,
    user_id: USER_ID,
    vault_id: VAULT_ID,
    item_type: 'password',
    updated_at: '2026-04-30T10:00:00.000Z',
    encrypted_data: await encryptItemEnvelopeV2({ title: id, password: 'secret' }, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: id,
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    }),
  };
}

function snapshot(items: ServerVaultItemV2[], categories: ServerVaultCategoryV2[]): OfflineVaultSnapshot {
  return {
    userId: USER_ID,
    vaultId: VAULT_ID,
    items: items.map((entry) => ({
      ...entry,
      title: '',
      category_id: null,
      created_at: '2026-04-30T10:00:00.000Z',
      icon_url: null,
      is_favorite: null,
      last_used_at: null,
      sort_order: null,
      updated_at: entry.updated_at ?? '2026-04-30T10:00:00.000Z',
      website_url: null,
      item_type: 'password',
    })),
    categories: categories.map((entry) => ({
      id: entry.id,
      user_id: entry.user_id,
      name: entry.name,
      icon: entry.icon ?? null,
      color: entry.color ?? null,
      parent_id: entry.parent_id ?? null,
      sort_order: entry.sort_order ?? null,
      created_at: '2026-04-30T10:00:00.000Z',
      updated_at: entry.updated_at ?? '2026-04-30T10:00:00.000Z',
    })),
    lastSyncedAt: '2026-04-30T10:00:00.000Z',
    updatedAt: '2026-04-30T10:00:00.000Z',
  };
}

async function saveRetryForSnapshot(currentSnapshot: OfflineVaultSnapshot): Promise<string> {
  const snapshotDigest = await computeVaultSnapshotDigest({
    items: currentSnapshot.items,
    categories: currentSnapshot.categories,
  });
  await saveManifestPersistRetryRecord({
    userId: USER_ID,
    vaultId: VAULT_ID,
    snapshotDigest,
    lastErrorCode: 'manifest_persist_failed',
  });
  return snapshotDigest;
}

describe('Vault Integrity V2 runtime bridge', () => {
  beforeEach(async () => {
    manifestStore.loadServerManifestEnvelopeV2.mockReset();
    manifestStore.persistServerManifestEnvelopeV2.mockReset();
    await removeManifestHighWaterMark(USER_ID, VAULT_ID).catch(() => undefined);
    await removeManifestPersistRetryRecord(USER_ID, VAULT_ID).catch(() => undefined);
  });

  it('evaluates an existing server manifest during runtime verification', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      evaluationSource: 'manual_recheck',
    })).resolves.toMatchObject({
      mode: 'healthy',
      itemCount: 1,
      quarantinedItems: [],
    });
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      keyId: KEY_ID,
    });
  });

  it('keeps a manifest hash mismatch as a precise active V2 quarantine reason', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });
    const tamperedItems = [{ ...items[0], encrypted_data: `${items[0].encrypted_data.slice(0, -1)}A` }];

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(tamperedItems, categories),
      vaultKey: key,
      trustedRecoveryState: {
        trustedRecoveryAvailable: true,
        trustedSnapshotItemsById: { 'item-1': snapshot(items, categories).items[0] },
        trustedSnapshot: snapshot(items, categories),
      },
      evaluationSource: 'manual_recheck',
    })).resolves.toMatchObject({
      mode: 'quarantine',
      quarantinedItems: [expect.objectContaining({
        id: 'item-1',
        reason: 'item_manifest_hash_mismatch',
      })],
    });
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
    });
  });

  it('blocks a server manifest older than the local high-water mark', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 10,
      categories,
      items,
      vaultKey: key,
    });
    await saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 11,
      manifestHash: 'newer-local-hash',
      keyId: KEY_ID,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 10,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      evaluationSource: 'manual_recheck',
    })).resolves.toMatchObject({
      mode: 'blocked',
      blockedReason: 'manifest_rollback_detected',
      quarantinedItems: [],
    });
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 11,
      manifestHash: 'newer-local-hash',
    });
  });

  it('refuses first-run TOFU when a trusted local snapshot contradicts the server manifest', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });
    const conflictingSnapshot = snapshot(
      [{ ...items[0], encrypted_data: `${items[0].encrypted_data.slice(0, -1)}A` }],
      categories,
    );

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      trustedRecoveryState: {
        trustedRecoveryAvailable: true,
        trustedSnapshotItemsById: { 'item-1': conflictingSnapshot.items[0] },
        trustedSnapshot: conflictingSnapshot,
      },
      evaluationSource: 'manual_recheck',
    })).resolves.toMatchObject({
      mode: 'integrity_unknown',
      nonTamperReason: 'manifest_snapshot_conflict',
      quarantinedItems: [],
    });
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toBeNull();
  });

  it('does not turn stale cached V2 snapshots into active item quarantine', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });
    const staleCachedItems = [{ ...items[0], encrypted_data: `${items[0].encrypted_data.slice(0, -1)}A` }];

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(staleCachedItems, categories),
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'cache',
    })).resolves.toMatchObject({
      mode: 'revalidation_failed',
      quarantinedItems: [],
    });
  });

  it('does not persist a Manifest V2 over legacy item envelopes', async () => {
    const key = await testKey();
    const result = await persistRuntimeManifestV2ForTrustedSnapshot({
      userId: USER_ID,
      snapshot: snapshot([{
        id: 'legacy-1',
        user_id: USER_ID,
        vault_id: VAULT_ID,
        item_type: 'password',
        encrypted_data: 'sv-vault-v1:legacy',
      }], [category()]),
      vaultKey: key,
    });

    expect(result).toBe('skipped_legacy_items');
    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
  });

  it('persists a trusted item delete as a Manifest V2 tombstone during runtime refresh', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1'), await item(key, 'item-2')];
    const currentBundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: currentBundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: currentBundle.envelope,
    });

    await expect(persistRuntimeManifestV2ForTrustedSnapshot({
      userId: USER_ID,
      snapshot: snapshot([items[1]], categories),
      vaultKey: key,
      trustedMutation: { itemIds: new Set(['item-1']) },
    })).resolves.toBe('persisted');

    expect(manifestStore.persistServerManifestEnvelopeV2).toHaveBeenCalledWith(expect.objectContaining({
      expectedPreviousManifestRevision: 1,
      expectedPreviousManifestHash: currentBundle.manifestHash,
    }));
    const persisted = manifestStore.persistServerManifestEnvelopeV2.mock.calls[0]?.[0];
    const verified = await verifyVaultManifestV2({
      envelope: persisted.envelope,
      key,
      expectedUserId: USER_ID,
      expectedVaultId: VAULT_ID,
      expectedKeyId: KEY_ID,
    });

    expect(persisted.envelope.manifestRevision).toBe(2);
    expect(verified).toMatchObject({
      ok: true,
      manifest: {
        previousManifestHash: currentBundle.manifestHash,
        items: [expect.objectContaining({ itemId: 'item-2' })],
        tombstones: [expect.objectContaining({
          itemId: 'item-1',
          deletedAtManifestRevision: 2,
        })],
      },
      manifestHash: persisted.manifestHash,
    });
  });

  it('retries a pending Manifest V2 persist only when the snapshot digest matches', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const currentSnapshot = snapshot(items, categories);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue(null);
    manifestStore.persistServerManifestEnvelopeV2.mockResolvedValue(undefined);
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'digest-1',
      lastErrorCode: 'manifest_persist_failed',
    });

    await expect(retryPendingRuntimeManifestV2ForSnapshot({
      userId: USER_ID,
      snapshot: currentSnapshot,
      vaultKey: key,
      snapshotDigest: 'digest-1',
    })).resolves.toMatchObject({ status: 'persisted' });

    expect(manifestStore.persistServerManifestEnvelopeV2).toHaveBeenCalledTimes(1);
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
  });

  it('does not retry Manifest V2 persist when the snapshot digest differs', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'digest-1',
      lastErrorCode: 'manifest_persist_failed',
    });

    await expect(retryPendingRuntimeManifestV2ForSnapshot({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      snapshotDigest: 'digest-2',
    })).resolves.toMatchObject({
      status: 'snapshot_mismatch',
      errorCode: 'manifest_retry_snapshot_mismatch',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: 'digest-1',
    });
  });

  it('does not retry Manifest V2 persist without an available current snapshot digest', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'digest-1',
      lastErrorCode: 'manifest_persist_failed',
    });

    await expect(retryPendingRuntimeManifestV2ForSnapshot({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      snapshotDigest: null,
    })).resolves.toMatchObject({
      status: 'snapshot_digest_unavailable',
      errorCode: 'manifest_retry_snapshot_digest_unavailable',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
  });

  it('allows pending Manifest V2 retry after a normal remote runtime decision', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const currentSnapshot = snapshot(items, categories);
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    const retryDigest = await saveRetryForSnapshot(currentSnapshot);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: currentSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'healthy',
      quarantinedItems: [],
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).toHaveBeenCalledTimes(1);
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 2,
    });
    expect(retryDigest).toEqual(expect.any(String));
  });

  it('blocks pending Manifest V2 retry after an item quarantine runtime decision', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    const tamperedSnapshot = snapshot(
      [{ ...items[0], encrypted_data: `${items[0].encrypted_data.slice(0, -1)}A` }],
      categories,
    );
    const retryDigest = await saveRetryForSnapshot(tamperedSnapshot);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: tamperedSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'quarantine',
      quarantinedItems: [expect.objectContaining({ id: 'item-1' })],
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: retryDigest,
    });
  });

  it('blocks pending Manifest V2 retry after a rollback safe-mode runtime decision', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const currentSnapshot = snapshot(items, categories);
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    await saveManifestHighWaterMark({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 2,
      manifestHash: 'newer-local-hash',
      keyId: KEY_ID,
    });
    const retryDigest = await saveRetryForSnapshot(currentSnapshot);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: currentSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'blocked',
      blockedReason: 'manifest_rollback_detected',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: retryDigest,
    });
  });

  it('blocks pending Manifest V2 retry for a normal cached snapshot', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const currentSnapshot = snapshot(items, categories);
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    const retryDigest = await saveRetryForSnapshot(currentSnapshot);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: currentSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'cache',
    })).resolves.toMatchObject({
      mode: 'healthy',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: retryDigest,
    });
  });

  it('blocks pending Manifest V2 retry after missing remote runtime decision', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const manifestWithItem = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    const missingSnapshot = snapshot([], categories);
    const missingRetryDigest = await saveRetryForSnapshot(missingSnapshot);
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: manifestWithItem.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: manifestWithItem.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: missingSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'integrity_unknown',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: missingRetryDigest,
    });
  });

  it('retries and re-evaluates manifest for orphan remote decision when snapshot matches pending retry', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const emptyManifest = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items: [],
      vaultKey: key,
    });
    const orphanSnapshot = snapshot(items, categories);
    await saveRetryForSnapshot(orphanSnapshot);

    let latestRecord: {
      manifestRevision: number;
      manifestHash: string;
      previousManifestHash: string | null;
      envelope: unknown;
    } = {
      manifestRevision: 1,
      manifestHash: emptyManifest.manifestHash,
      previousManifestHash: null,
      envelope: emptyManifest.envelope,
    };
    manifestStore.loadServerManifestEnvelopeV2.mockImplementation(async () => ({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      ...latestRecord,
    }));
    manifestStore.persistServerManifestEnvelopeV2.mockImplementation(async (data: {
      envelope: { manifestRevision: number };
      manifestHash: string;
      previousManifestHash: string | null;
    }) => {
      latestRecord = {
        manifestRevision: data.envelope.manifestRevision,
        manifestHash: data.manifestHash,
        previousManifestHash: data.previousManifestHash,
        envelope: data.envelope,
      };
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: orphanSnapshot,
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'healthy',
      quarantinedItems: [],
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).toHaveBeenCalledTimes(1);
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 2,
    });
  });

  it('clears stale pending retry for orphan remote decision when snapshot digest does not match', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const emptyManifest = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items: [],
      vaultKey: key,
    });
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'stale-orphan-digest',
      lastErrorCode: 'manifest_persist_failed',
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: emptyManifest.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: emptyManifest.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      evaluationSource: 'manual_recheck',
      snapshotSource: 'remote',
    })).resolves.toMatchObject({
      mode: 'integrity_unknown',
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
  });

  it('clears a stale pending Manifest V2 retry after normal remote runtime verification', async () => {
    const key = await testKey();
    const categories = [category()];
    const items = [await item(key, 'item-1')];
    const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      manifestRevision: 1,
      categories,
      items,
      vaultKey: key,
    });
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'stale-digest',
      lastErrorCode: 'manifest_persist_failed',
    });
    manifestStore.loadServerManifestEnvelopeV2.mockResolvedValue({
      userId: USER_ID,
      vaultId: VAULT_ID,
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
      previousManifestHash: null,
      keyId: KEY_ID,
      envelope: bundle.envelope,
    });

    await expect(evaluateRuntimeVaultIntegrityV2({
      userId: USER_ID,
      snapshot: snapshot(items, categories),
      vaultKey: key,
      evaluationSource: 'manual_recheck',
    })).resolves.toMatchObject({
      mode: 'healthy',
      quarantinedItems: [],
    });

    expect(manifestStore.persistServerManifestEnvelopeV2).not.toHaveBeenCalled();
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
    await expect(loadManifestHighWaterMark(USER_ID, VAULT_ID)).resolves.toMatchObject({
      manifestRevision: 1,
      manifestHash: bundle.manifestHash,
    });
  });
});
