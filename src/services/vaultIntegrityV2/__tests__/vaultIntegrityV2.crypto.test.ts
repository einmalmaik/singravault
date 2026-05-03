import { describe, expect, it } from 'vitest';
import type { VaultItemData } from '@/services/cryptoService';
import {
  buildVaultItemAadV2,
  buildVaultManifestAadV2,
  computeCategoriesHashV2,
  detectManifestRollback,
  encryptItemEnvelopeV2,
  encryptVaultManifestV2,
  evaluateVaultIntegrityV2,
  hashVaultItemEnvelopeV2,
  parseVaultItemEnvelopeV2,
  serializeVaultItemEnvelopeV2,
  verifyAndDecryptItemEnvelopeV2,
  verifyCategoriesAgainstManifestV2,
  verifyVaultItemAadV2,
  verifyVaultManifestV2,
  type ServerVaultCategoryV2,
  type ServerVaultItemV2,
  type VaultManifestV2,
} from '../index';

const USER_ID = 'user-1';
const VAULT_ID = 'vault-1';
const KEY_ID = 'user-key-v1';

async function testKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

function makeCategory(overrides: Partial<ServerVaultCategoryV2> = {}): ServerVaultCategoryV2 {
  return {
    id: 'cat-1',
    user_id: USER_ID,
    name: 'enc:cat:v1:name',
    icon: null,
    color: 'enc:cat:v1:blue',
    parent_id: null,
    sort_order: null,
    ...overrides,
  };
}

async function makeItem(
  key: CryptoKey,
  overrides: Partial<{
    itemId: string;
    userId: string;
    vaultId: string;
    keyId: string;
    itemRevision: number;
    itemType: string;
    plaintext: VaultItemData;
  }> = {},
): Promise<ServerVaultItemV2> {
  const itemId = overrides.itemId ?? 'item-1';
  const itemType = overrides.itemType ?? 'password';
  return {
    id: itemId,
    user_id: USER_ID,
    vault_id: VAULT_ID,
    item_type: itemType,
    encrypted_data: await encryptItemEnvelopeV2(overrides.plaintext ?? { title: itemId, password: 'secret' }, key, {
      vaultId: overrides.vaultId ?? VAULT_ID,
      userId: overrides.userId ?? USER_ID,
      itemId,
      itemType,
      keyId: overrides.keyId ?? KEY_ID,
      itemRevision: overrides.itemRevision ?? 1,
      schemaVersion: 1,
    }),
    updated_at: '2026-04-30T10:00:00.000Z',
  };
}

async function makeManifest(
  key: CryptoKey,
  items: ServerVaultItemV2[],
  categories: ServerVaultCategoryV2[],
  overrides: Partial<VaultManifestV2> = {},
) {
  const manifest: VaultManifestV2 = {
    manifestVersion: 2,
    vaultId: VAULT_ID,
    userId: USER_ID,
    keysetVersion: 1,
    manifestRevision: 1,
    createdAt: '2026-04-30T10:00:00.000Z',
    categoriesHash: await computeCategoriesHashV2(categories),
    items: await Promise.all(items.map(async (item) => {
      const parsed = parseVaultItemEnvelopeV2(item.encrypted_data);
      if (!parsed.ok) {
        throw new Error('test item must be V2');
      }
      return {
        itemId: item.id,
        itemType: parsed.envelope.itemType,
        itemRevision: parsed.envelope.itemRevision,
        envelopeVersion: 2 as const,
        keyId: parsed.envelope.keyId,
        envelopeHash: await hashVaultItemEnvelopeV2(item.encrypted_data),
      };
    })),
    ...overrides,
  };
  return {
    manifest,
    envelope: await encryptVaultManifestV2(manifest, key, KEY_ID),
  };
}

describe('Vault Integrity V2 crypto and manifest verification', () => {
  it('builds Item-AAD V2 with all required context fields', () => {
    const aad = buildVaultItemAadV2({
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'totp',
      keyId: KEY_ID,
      itemRevision: 4,
      schemaVersion: 1,
    });

    expect(aad).toEqual({
      purpose: 'vault_item',
      envelopeVersion: 2,
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'totp',
      keyId: KEY_ID,
      itemRevision: 4,
      schemaVersion: 1,
    });
  });

  it('rejects Item-AAD V2 mismatches for vault, user, item, key, revision and schema', () => {
    const expected = buildVaultItemAadV2({
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    });

    for (const override of [
      { vaultId: 'vault-other' },
      { userId: 'user-other' },
      { itemId: 'item-other' },
      { keyId: 'key-other' },
      { itemRevision: 2 },
      { schemaVersion: 2 },
      { itemType: 'totp' },
    ]) {
      expect(verifyVaultItemAadV2({ ...expected, ...override }, expected)).toBe(false);
    }
  });

  it('round-trips an Item-Envelope V2 and rejects wrong item context', async () => {
    const key = await testKey();
    const encrypted = await encryptItemEnvelopeV2({ title: 'Mail', password: 'secret' }, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    });

    await expect(verifyAndDecryptItemEnvelopeV2(encrypted, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    })).resolves.toMatchObject({ ok: true, data: { title: 'Mail', password: 'secret' } });

    await expect(verifyAndDecryptItemEnvelopeV2(encrypted, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-other',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    })).resolves.toMatchObject({ ok: false, reason: 'item_aad_mismatch' });
  });

  it('reports malformed envelopes and AEAD auth failures without exposing plaintext', async () => {
    const key = await testKey();
    await expect(verifyAndDecryptItemEnvelopeV2('sv-vault-v2:not-base64-json', key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    })).resolves.toMatchObject({ ok: false, reason: 'item_envelope_malformed' });

    const item = await makeItem(key);
    const parsed = parseVaultItemEnvelopeV2(item.encrypted_data);
    if (!parsed.ok) throw new Error('expected v2 envelope');
    const tamperedEnvelope = {
      ...parsed.envelope,
      ciphertext: `${parsed.envelope.ciphertext.slice(0, -2)}AA`,
    };
    const tampered = serializeVaultItemEnvelopeV2(tamperedEnvelope);
    await expect(verifyAndDecryptItemEnvelopeV2(tampered, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    })).resolves.toMatchObject({ ok: false, reason: 'aead_auth_failed' });
  });

  it('authenticates Manifest V2 and detects auth-tag tampering', async () => {
    const key = await testKey();
    const categories = [makeCategory()];
    const items = [await makeItem(key)];
    const { envelope } = await makeManifest(key, items, categories);

    await expect(verifyVaultManifestV2({
      envelope,
      key,
      expectedUserId: USER_ID,
      expectedVaultId: VAULT_ID,
      expectedKeyId: KEY_ID,
    })).resolves.toMatchObject({ ok: true, manifest: expect.objectContaining({ manifestVersion: 2 }) });

    await expect(verifyVaultManifestV2({
      envelope: { ...envelope, ciphertext: `${envelope.ciphertext.slice(0, -2)}AA` },
      key,
      expectedUserId: USER_ID,
      expectedVaultId: VAULT_ID,
      expectedKeyId: KEY_ID,
    })).resolves.toMatchObject({ ok: false, reason: 'manifest_auth_failed' });
  });

  it('rejects relabeled Manifest V2 envelopes whose authenticated context belongs to another vault', async () => {
    const key = await testKey();
    const categories = [makeCategory()];
    const items = [await makeItem(key)];
    const { envelope } = await makeManifest(key, items, categories);

    await expect(verifyVaultManifestV2({
      envelope: {
        ...envelope,
        vaultId: 'vault-other',
        userId: 'user-other',
      },
      key,
      expectedUserId: 'user-other',
      expectedVaultId: 'vault-other',
      expectedKeyId: KEY_ID,
    })).resolves.toMatchObject({ ok: false, reason: 'manifest_invalid' });
  });

  it('detects Manifest V2 rollback against the local high-water mark', async () => {
    const key = await testKey();
    const categories = [makeCategory()];
    const items = [await makeItem(key)];
    const { manifest } = await makeManifest(key, items, categories);
    const rollback = detectManifestRollback(manifest, 'hash-old', {
      manifestRevision: manifest.manifestRevision + 1,
      manifestHash: 'hash-new',
    });

    expect(rollback).toMatchObject({
      ok: false,
      diagnostics: [expect.objectContaining({ code: 'manifest_rollback_detected' })],
    });
  });

  it('sends category manipulation to Safe Mode', async () => {
    const key = await testKey();
    const categories = [makeCategory()];
    const items = [await makeItem(key)];
    const { manifest, envelope } = await makeManifest(key, items, categories);

    await expect(verifyCategoriesAgainstManifestV2(categories, manifest)).resolves.toMatchObject({ ok: true });

    const decision = await evaluateVaultIntegrityV2({
      userId: USER_ID,
      vaultId: VAULT_ID,
      serverItems: items,
      serverCategories: [makeCategory({ name: 'enc:cat:v1:tampered' })],
      serverManifestEnvelope: envelope,
      localSnapshots: [],
      pendingMutations: [],
      unlockContext: {
        vaultKeyVerified: true,
        vaultKey: key,
        keyId: KEY_ID,
        protectionMode: 'master_only',
      },
      evaluationSource: 'manual_recheck',
    });

    expect(decision).toMatchObject({
      mode: 'safe_mode',
      reason: 'category_structure_mismatch',
    });
  });

  it('builds Manifest-AAD V2 for the manifest domain only', () => {
    expect(buildVaultManifestAadV2({
      vaultId: VAULT_ID,
      userId: USER_ID,
      keyId: KEY_ID,
      manifestRevision: 3,
    })).toEqual({
      purpose: 'vault_manifest',
      envelopeVersion: 2,
      vaultId: VAULT_ID,
      userId: USER_ID,
      keyId: KEY_ID,
      manifestVersion: 2,
      manifestRevision: 3,
    });
  });
});
