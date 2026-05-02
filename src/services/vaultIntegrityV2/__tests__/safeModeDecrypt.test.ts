import { describe, expect, it } from 'vitest';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  decryptTrustedRecoverySnapshotItem,
  encryptItemEnvelopeV2,
} from '../index';

const USER_ID = 'user-safe';
const VAULT_ID = 'vault-safe';
const KEY_ID = 'key-safe';

async function testKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function trustedItem(key: CryptoKey): Promise<OfflineVaultSnapshot['items'][number]> {
  return {
    id: 'item-1',
    user_id: USER_ID,
    vault_id: VAULT_ID,
    title: 'Item',
    website_url: null,
    icon_url: null,
    item_type: 'password',
    category_id: null,
    is_favorite: null,
    sort_order: null,
    last_used_at: null,
    created_at: '2026-04-30T10:00:00.000Z',
    updated_at: '2026-04-30T10:00:00.000Z',
    encrypted_data: await encryptItemEnvelopeV2({ title: 'Item', password: 'secret' }, key, {
      vaultId: VAULT_ID,
      userId: USER_ID,
      itemId: 'item-1',
      itemType: 'password',
      keyId: KEY_ID,
      itemRevision: 1,
      schemaVersion: 1,
    }),
  };
}

describe('safe mode recovery decrypt', () => {
  it('decrypts only with an explicit trusted recovery context', async () => {
    const key = await testKey();
    const item = await trustedItem(key);

    await expect(decryptTrustedRecoverySnapshotItem({
      item,
      vaultKey: key,
      context: {
        source: 'trusted_recovery_snapshot',
        reason: 'safe_mode_export',
        snapshotId: 'trusted-recovery:test',
        userId: USER_ID,
        vaultId: VAULT_ID,
      },
    })).resolves.toMatchObject({
      title: 'Item',
      password: 'secret',
    });
  });

  it('rejects scope-mismatched items instead of acting as a generic decrypt bypass', async () => {
    const key = await testKey();
    const item = await trustedItem(key);

    await expect(decryptTrustedRecoverySnapshotItem({
      item: { ...item, vault_id: 'other-vault' },
      vaultKey: key,
      context: {
        source: 'trusted_recovery_snapshot',
        reason: 'safe_mode_export',
        snapshotId: 'trusted-recovery:test',
        userId: USER_ID,
        vaultId: VAULT_ID,
      },
    })).rejects.toMatchObject({ code: 'snapshot_scope_mismatch' });
  });
});
