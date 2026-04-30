import { describe, expect, it } from 'vitest';
import type { VaultItemData } from '@/services/cryptoService';
import {
  buildManifestEnvelopeV2FromVerifiedInputs,
  buildTrustedItemDeleteMutationV2,
  buildTrustedItemUpsertMutationV2,
  encryptItemEnvelopeV2,
  encryptVaultManifestV2,
  evaluateVaultIntegrityV2,
  hashVaultItemEnvelopeV2,
  migrateVaultIntegrityToV2,
  parseVaultItemEnvelopeV2,
  reconcileQuarantineRecordsV2,
  restoreVaultItemFromTrustedSnapshotV2,
  serializeVaultItemEnvelopeV2,
  type ServerVaultCategoryV2,
  type ServerVaultItemV2,
  type TrustedLocalSnapshotMetadata,
  type VaultManifestV2,
} from '../index';

const USER_ID = 'user-1';
const VAULT_ID = 'vault-1';
const KEY_ID = 'user-key-v1';

async function testKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function category(overrides: Partial<ServerVaultCategoryV2> = {}): ServerVaultCategoryV2 {
  return {
    id: 'cat-1',
    user_id: USER_ID,
    name: 'enc:cat:v1:name',
    icon: null,
    color: null,
    parent_id: null,
    sort_order: null,
    ...overrides,
  };
}

async function item(
  key: CryptoKey,
  id: string,
  plaintext: VaultItemData = { title: id, password: 'secret' },
  revision = 1,
): Promise<ServerVaultItemV2> {
  return {
    id,
    user_id: USER_ID,
    vault_id: VAULT_ID,
    item_type: plaintext.itemType ?? 'password',
    updated_at: '2026-04-30T10:00:00.000Z',
    encrypted_data: await encryptItemEnvelopeV2(plaintext, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: id,
      itemType: plaintext.itemType ?? 'password',
      keyId: KEY_ID,
      itemRevision: revision,
      schemaVersion: 1,
    }),
  };
}

async function vaultFixture(count = 2) {
  const key = await testKey();
  const categories = [category()];
  const items = await Promise.all(Array.from({ length: count }, (_, index) => item(key, `item-${index + 1}`)));
  const bundle = await buildManifestEnvelopeV2FromVerifiedInputs({
    userId: USER_ID,
    vaultId: VAULT_ID,
    keyId: KEY_ID,
    keysetVersion: 1,
    manifestRevision: 1,
    categories,
    items,
    vaultKey: key,
    createdAt: '2026-04-30T10:00:00.000Z',
  });
  const snapshot: TrustedLocalSnapshotMetadata = {
    snapshotVersion: 2,
    snapshotId: 'snapshot-1',
    userId: USER_ID,
    vaultId: VAULT_ID,
    manifestHash: bundle.manifestHash,
    manifestRevision: 1,
    createdAt: '2026-04-30T10:00:00.000Z',
    itemCount: items.length,
    categoryCount: categories.length,
    recoverableItemIds: items.map((fixtureItem) => fixtureItem.id),
  };

  return { key, categories, items, ...bundle, snapshot };
}

async function evaluate(input: Awaited<ReturnType<typeof vaultFixture>>, overrides: Partial<{
  items: ServerVaultItemV2[];
  categories: ServerVaultCategoryV2[];
  manifest: VaultManifestV2;
  envelope: unknown;
  snapshots: TrustedLocalSnapshotMetadata[];
  vaultKeyVerified: boolean;
  vaultKey: CryptoKey;
}> = {}) {
  return evaluateVaultIntegrityV2({
    userId: USER_ID,
    vaultId: VAULT_ID,
    serverItems: overrides.items ?? input.items,
    serverCategories: overrides.categories ?? input.categories,
    serverManifestEnvelope: overrides.envelope as never ?? input.envelope,
    localSnapshots: overrides.snapshots ?? [input.snapshot],
    pendingMutations: [],
    unlockContext: {
      vaultKeyVerified: overrides.vaultKeyVerified ?? true,
      vaultKey: overrides.vaultKey ?? input.key,
      keyId: KEY_ID,
      protectionMode: 'master_only',
    },
    evaluationSource: 'manual_recheck',
  });
}

describe('Vault Integrity V2 service flows', () => {
  it('keeps a healthy authenticated vault normal', async () => {
    const fixture = await vaultFixture(17);

    await expect(evaluate(fixture)).resolves.toMatchObject({
      mode: 'normal',
      itemCount: 17,
      healthyItemIds: expect.arrayContaining(['item-1', 'item-17']),
    });
  });

  it('classifies real encrypted_data manipulation as one active item quarantine', async () => {
    const fixture = await vaultFixture(3);
    const tamperedItems = fixture.items.map((fixtureItem) => fixtureItem.id === 'item-2'
      ? { ...fixtureItem, encrypted_data: `${fixtureItem.encrypted_data.slice(0, -1)}A` }
      : fixtureItem);

    const decision = await evaluate(fixture, { items: tamperedItems });

    expect(decision).toMatchObject({
      mode: 'item_quarantine',
      quarantinedItems: [
        expect.objectContaining({
          itemId: 'item-2',
          reason: 'item_manifest_hash_mismatch',
          recoverable: true,
        }),
      ],
      healthyItemIds: ['item-1', 'item-3'],
    });
  });

  it('separates AEAD auth failure from manifest hash mismatch when the manifest commits to the observed envelope', async () => {
    const fixture = await vaultFixture(1);
    const parsed = parseVaultItemEnvelopeV2(fixture.items[0].encrypted_data);
    if (!parsed.ok) throw new Error('expected V2 envelope');
    const tamperedEnvelope = {
      ...parsed.envelope,
      ciphertext: `${parsed.envelope.ciphertext.slice(0, -2)}AA`,
    };
    const tamperedItem = {
      ...fixture.items[0],
      encrypted_data: serializeVaultItemEnvelopeV2(tamperedEnvelope),
    };
    const tamperedManifest: VaultManifestV2 = {
      ...fixture.manifest,
      items: [{
        ...fixture.manifest.items[0],
        envelopeHash: await hashVaultItemEnvelopeV2(tamperedItem.encrypted_data),
      }],
    };
    const tamperedManifestEnvelope = await encryptVaultManifestV2(tamperedManifest, fixture.key, KEY_ID);

    const decision = await evaluate(fixture, {
      items: [tamperedItem],
      envelope: tamperedManifestEnvelope,
    });

    expect(decision).toMatchObject({
      mode: 'item_quarantine',
      quarantinedItems: [expect.objectContaining({ itemId: 'item-1', reason: 'aead_auth_failed' })],
    });
  });

  it('does not turn wrong or stale key state into active item quarantine', async () => {
    const fixture = await vaultFixture(2);
    const decision = await evaluate(fixture, { vaultKeyVerified: false });

    expect(decision).toMatchObject({
      mode: 'revalidation_failed',
      reason: 'vault_key_not_verified',
      diagnostics: [expect.objectContaining({ code: 'vault_key_not_verified' })],
    });
  });

  it('reports Device-Key stale state as revalidation, not quarantine', async () => {
    const fixture = await vaultFixture(2);
    const decision = await evaluateVaultIntegrityV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      serverItems: fixture.items,
      serverCategories: fixture.categories,
      serverManifestEnvelope: fixture.envelope,
      localSnapshots: [],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: fixture.key,
        keyId: KEY_ID,
        protectionMode: 'device_key_required',
        deviceKeyStateStale: true,
      },
      evaluationSource: 'sync',
    });

    expect(decision).toMatchObject({ mode: 'revalidation_failed', reason: 'device_key_state_stale' });
  });

  it('keeps orphan remote and missing remote out of active quarantine', async () => {
    const fixture = await vaultFixture(2);
    const orphan = await item(fixture.key, 'orphan-1');
    const decision = await evaluate(fixture, {
      items: [fixture.items[0], orphan],
      snapshots: [],
    });

    expect(decision).toMatchObject({
      mode: 'missing_remote',
      missingItems: [expect.objectContaining({ itemId: 'item-2', recoverable: false })],
      healthyItemIds: ['item-1'],
      diagnostics: expect.arrayContaining([
        expect.objectContaining({ code: 'orphan_remote', itemId: 'orphan-1' }),
        expect.objectContaining({ code: 'missing_on_server', itemId: 'item-2' }),
      ]),
    });
    expect('quarantinedItems' in decision).toBe(false);
  });

  it('makes duplicate active server records an active integrity finding only for that item id', async () => {
    const fixture = await vaultFixture(2);
    const decision = await evaluate(fixture, {
      items: [fixture.items[0], fixture.items[0], fixture.items[1]],
    });

    expect(decision).toMatchObject({
      mode: 'item_quarantine',
      quarantinedItems: [expect.objectContaining({ itemId: 'item-1', reason: 'duplicate_active_item_record' })],
      healthyItemIds: ['item-2'],
    });
  });

  it('applies a legitimate item mutation through AAD V2 and increments Manifest V2', async () => {
    const fixture = await vaultFixture(1);
    const mutation = await buildTrustedItemUpsertMutationV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      vaultKey: fixture.key,
      currentManifest: fixture.manifest,
      categories: fixture.categories,
      existingItems: fixture.items,
      itemId: 'item-1',
      itemType: 'password',
      plaintext: { title: 'updated', password: 'new-secret' },
    });

    expect(mutation.manifest.manifestRevision).toBe(2);
    expect(mutation.manifest.previousManifestHash).toBe(fixture.manifestHash);
    await expect(evaluateVaultIntegrityV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      serverItems: [mutation.item],
      serverCategories: fixture.categories,
      serverManifestEnvelope: mutation.manifestEnvelope,
      localSnapshots: [],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: fixture.key,
        keyId: KEY_ID,
        protectionMode: 'master_only',
      },
      evaluationSource: 'sync',
    })).resolves.toMatchObject({ mode: 'normal', manifestRevision: 2 });
  });

  it('applies a legitimate item delete as a Manifest V2 tombstone without missing-remote quarantine', async () => {
    const fixture = await vaultFixture(2);
    const deletion = await buildTrustedItemDeleteMutationV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      vaultKey: fixture.key,
      currentManifest: fixture.manifest,
      categories: fixture.categories,
      existingItems: fixture.items,
      itemId: 'item-1',
      deletedAt: '2026-04-30T11:00:00.000Z',
      deletedByDeviceId: 'device-1',
    });

    expect(deletion.manifest.manifestRevision).toBe(2);
    expect(deletion.manifest.previousManifestHash).toBe(fixture.manifestHash);
    expect(deletion.manifest.tombstones).toEqual([
      expect.objectContaining({
        itemId: 'item-1',
        deletedAtManifestRevision: 2,
        deletedByDeviceId: 'device-1',
      }),
    ]);

    await expect(evaluateVaultIntegrityV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      serverItems: [fixture.items[1]],
      serverCategories: fixture.categories,
      serverManifestEnvelope: deletion.manifestEnvelope,
      localSnapshots: [fixture.snapshot],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: fixture.key,
        keyId: KEY_ID,
        protectionMode: 'master_only',
      },
      evaluationSource: 'sync',
    })).resolves.toMatchObject({
      mode: 'normal',
      manifestRevision: 2,
      itemCount: 1,
      healthyItemIds: ['item-2'],
    });
  });

  it('restores only from a trusted snapshot and writes new AAD V2 plus Manifest V2', async () => {
    const fixture = await vaultFixture(1);
    const restored = await restoreVaultItemFromTrustedSnapshotV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      keysetVersion: 1,
      vaultKey: fixture.key,
      currentManifest: fixture.manifest,
      categories: fixture.categories,
      serverItems: fixture.items,
      snapshot: fixture.snapshot,
      itemId: 'item-1',
      reason: 'item_manifest_hash_mismatch',
      itemType: 'password',
      trustedPlaintext: { title: 'restored', password: 'from-snapshot' },
    });

    expect(restored.manifest.manifestRevision).toBe(2);
    await expect(evaluateVaultIntegrityV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      serverItems: [restored.item],
      serverCategories: fixture.categories,
      serverManifestEnvelope: restored.manifestEnvelope,
      localSnapshots: [fixture.snapshot],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: fixture.key,
        keyId: KEY_ID,
        protectionMode: 'master_only',
      },
      evaluationSource: 'safe_mode_recovery',
    })).resolves.toMatchObject({ mode: 'normal' });
  });

  it('migrates R3 diagnostic records to V2 without blessing stale phantom quarantine', async () => {
    const fixture = await vaultFixture(17);
    const migration = await migrateVaultIntegrityToV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      vaultKeyVerified: true,
      vaultKey: fixture.key,
      serverItems: fixture.items,
      serverCategories: fixture.categories,
      oldQuarantineRecords: [
        { itemId: 'item-18', reason: 'missing_on_server' },
        { itemId: 'item-19', reason: 'unknown_on_server' },
        { itemId: 'item-20', reason: 'decrypt_failed' },
        { itemId: 'item-21', reason: 'stale_baseline_only' },
      ],
    });

    expect(migration).toMatchObject({
      status: 'migrated',
      migratedItemCount: 17,
    });

    const reconciled = reconcileQuarantineRecordsV2({
      legacyRecords: [
        { itemId: 'item-18', reason: 'missing_on_server' },
        { itemId: 'item-19', reason: 'unknown_on_server' },
        { itemId: 'item-20', reason: 'decrypt_failed' },
        { itemId: 'item-21', reason: 'stale_baseline_only' },
      ],
      manifestRevision: 1,
    });

    expect(reconciled.filter((record) => record.bucket === 'active_quarantine')).toEqual([]);
    expect(reconciled).toHaveLength(4);
  });

  it('makes migration idempotent when a valid V2 manifest already exists', async () => {
    const fixture = await vaultFixture(2);
    const migration = await migrateVaultIntegrityToV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      vaultKeyVerified: true,
      vaultKey: fixture.key,
      serverItems: fixture.items,
      serverCategories: fixture.categories,
      existingManifestEnvelope: fixture.envelope,
    });

    expect(migration).toEqual({
      status: 'already_migrated',
      manifestRevision: 1,
    });
  });

  it('blocks migration when legacy v1/no-AAD item envelopes still need re-encryption', async () => {
    const fixture = await vaultFixture(1);
    const migration = await migrateVaultIntegrityToV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      keyId: KEY_ID,
      vaultKeyVerified: true,
      vaultKey: fixture.key,
      serverItems: [{ ...fixture.items[0], encrypted_data: 'sv-vault-v1:legacy' }],
      serverCategories: fixture.categories,
    });

    expect(migration).toMatchObject({
      status: 'blocked',
      reason: 'legacy_items_require_reencrypt',
      diagnostics: [expect.objectContaining({ code: 'legacy_item_requires_migration', itemId: 'item-1' })],
    });
  });
});
