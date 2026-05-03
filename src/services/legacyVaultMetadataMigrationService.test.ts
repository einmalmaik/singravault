import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  migrateLegacyVaultItemEncryptionAndMetadata,
  migrateLegacyVaultItemMetadata,
} from './legacyVaultMetadataMigrationService';

const updateEq = vi.fn();
const update = vi.fn();
const from = vi.fn();
const upsertOfflineItemRow = vi.fn();

vi.mock('@/integrations/supabase/client', () => ({
  supabase: { from: (...args: unknown[]) => from(...args) },
}));

vi.mock('@/services/offlineVaultService', () => ({
  upsertOfflineItemRow: (...args: unknown[]) => upsertOfflineItemRow(...args),
}));

const legacyItem = {
  id: 'item-1',
  user_id: 'user-1',
  vault_id: 'vault-1',
  title: 'Legacy payroll login',
  website_url: 'https://payroll.example',
  icon_url: 'https://payroll.example/favicon.ico',
  item_type: 'totp',
  encrypted_data: 'old-ciphertext',
  category_id: 'cat-1',
  is_favorite: true,
  sort_order: 5,
  last_used_at: '2026-04-28T10:00:00.000Z',
  created_at: '2026-04-01T00:00:00.000Z',
  updated_at: '2026-04-28T10:00:00.000Z',
} as const;

describe('legacy vault metadata migration service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    updateEq.mockResolvedValue({ error: null });
    update.mockReturnValue({ eq: () => ({ eq: updateEq }) });
    from.mockReturnValue({ update });
  });

  it('merges legacy server metadata into encrypted payload and writes only neutral server fields', async () => {
    const encryptItem = vi.fn().mockResolvedValue('new-ciphertext');

    const result = await migrateLegacyVaultItemMetadata({
      userId: 'user-1',
      vaultId: 'vault-1',
      item: legacyItem as never,
      decryptedData: { password: 'secret' },
      canPersistRemote: true,
      encryptItem,
      now: () => new Date('2026-04-28T12:00:00.000Z'),
    });

    expect(encryptItem).toHaveBeenCalledWith({
      password: 'secret',
      title: 'Legacy payroll login',
      websiteUrl: 'https://payroll.example',
      itemType: 'totp',
      isFavorite: true,
      categoryId: 'cat-1',
    }, 'item-1');

    expect(update).toHaveBeenCalledWith(expect.objectContaining({
      encrypted_data: 'new-ciphertext',
      title: 'Encrypted Item',
      website_url: null,
      icon_url: null,
      item_type: 'password',
      is_favorite: false,
      category_id: null,
      sort_order: null,
      last_used_at: null,
    }));
    expect(updateEq).toHaveBeenCalledWith('user_id', 'user-1');
    expect(upsertOfflineItemRow).toHaveBeenCalledWith('user-1', expect.objectContaining({
      encrypted_data: 'new-ciphertext',
      title: 'Encrypted Item',
      website_url: null,
    }), 'vault-1');
    expect(result.migrated).toBe(true);
  });

  it('is idempotent for already neutral rows', async () => {
    const encryptItem = vi.fn();

    const result = await migrateLegacyVaultItemMetadata({
      userId: 'user-1',
      vaultId: 'vault-1',
      item: {
        ...legacyItem,
        title: 'Encrypted Item',
        website_url: null,
        icon_url: null,
        item_type: 'password',
        category_id: null,
        is_favorite: false,
        sort_order: null,
        last_used_at: null,
      } as never,
      decryptedData: { title: 'Already encrypted' },
      canPersistRemote: true,
      encryptItem,
    });

    expect(result.migrated).toBe(false);
    expect(encryptItem).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
    expect(upsertOfflineItemRow).not.toHaveBeenCalled();
  });

  it('keeps the unlocked item usable when the remote neutralization write fails', async () => {
    updateEq.mockResolvedValueOnce({ error: new Error('network unavailable') });
    const encryptItem = vi.fn().mockResolvedValue('new-ciphertext');

    const result = await migrateLegacyVaultItemMetadata({
      userId: 'user-1',
      vaultId: 'vault-1',
      item: legacyItem as never,
      decryptedData: { password: 'secret' },
      canPersistRemote: true,
      encryptItem,
    });

    expect(result).toMatchObject({
      migrated: false,
      decryptedData: {
        password: 'secret',
        title: 'Legacy payroll login',
        websiteUrl: 'https://payroll.example',
      },
      item: {
        title: 'Encrypted Item',
        website_url: null,
        item_type: 'password',
      },
    });
    expect(upsertOfflineItemRow).not.toHaveBeenCalled();
  });

  it('migrates legacy encryption and server metadata in one trusted write', async () => {
    const encryptItem = vi.fn().mockResolvedValue('aad-bound-ciphertext');

    const result = await migrateLegacyVaultItemEncryptionAndMetadata({
      userId: 'user-1',
      vaultId: 'vault-1',
      item: legacyItem as never,
      decryptedData: { password: 'secret' },
      canPersistRemote: true,
      encryptItem,
      now: () => new Date('2026-04-28T12:00:00.000Z'),
    });

    expect(encryptItem).toHaveBeenCalledWith({
      password: 'secret',
      title: 'Legacy payroll login',
      websiteUrl: 'https://payroll.example',
      itemType: 'totp',
      isFavorite: true,
      categoryId: 'cat-1',
    }, 'item-1');
    expect(update).toHaveBeenCalledWith(expect.objectContaining({
      encrypted_data: 'aad-bound-ciphertext',
      title: 'Encrypted Item',
      website_url: null,
      item_type: 'password',
      is_favorite: false,
      category_id: null,
    }));
    expect(upsertOfflineItemRow).toHaveBeenCalledWith('user-1', expect.objectContaining({
      encrypted_data: 'aad-bound-ciphertext',
      title: 'Encrypted Item',
      updated_at: '2026-04-28T12:00:00.000Z',
    }), 'vault-1');
    expect(result).toMatchObject({
      migrated: true,
      decryptedData: {
        password: 'secret',
        title: 'Legacy payroll login',
      },
    });
  });
});
