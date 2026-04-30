import { describe, expect, it, vi } from 'vitest';
import {
  buildManifestEnvelopeV2FromVerifiedInputs,
  encryptItemEnvelopeV2,
  evaluateRuntimeVaultIntegrityV2,
  persistRuntimeManifestV2ForTrustedSnapshot,
  type ServerVaultCategoryV2,
  type ServerVaultItemV2,
} from '../index';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';

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

describe('Vault Integrity V2 runtime bridge', () => {
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
});
