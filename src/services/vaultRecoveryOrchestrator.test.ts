import { beforeEach, describe, expect, it, vi } from 'vitest';

const cryptoMocks = vi.hoisted(() => ({
  decryptVaultItem: vi.fn(),
  decryptVaultItemForMigration: vi.fn(),
  encryptVaultItem: vi.fn(),
}));

const recoveryMocks = vi.hoisted(() => ({
  restoreQuarantinedItemFromTrustedSnapshot: vi.fn(),
  deleteQuarantinedItemFromVault: vi.fn(),
  indexTrustedSnapshotItems: vi.fn(),
}));

vi.mock('@/services/cryptoService', () => ({
  decryptVaultItem: (...args: unknown[]) => cryptoMocks.decryptVaultItem(...args),
  decryptVaultItemForMigration: (...args: unknown[]) => cryptoMocks.decryptVaultItemForMigration(...args),
  encryptVaultItem: (...args: unknown[]) => cryptoMocks.encryptVaultItem(...args),
}));

vi.mock('@/services/vaultQuarantineRecoveryService', () => ({
  restoreQuarantinedItemFromTrustedSnapshot: (...args: unknown[]) =>
    recoveryMocks.restoreQuarantinedItemFromTrustedSnapshot(...args),
  deleteQuarantinedItemFromVault: (...args: unknown[]) => recoveryMocks.deleteQuarantinedItemFromVault(...args),
  indexTrustedSnapshotItems: (...args: unknown[]) => recoveryMocks.indexTrustedSnapshotItems(...args),
}));

vi.mock('@/services/offlineVaultService', () => ({
  isAppOnline: () => true,
  getTrustedOfflineSnapshot: vi.fn(),
  saveTrustedOfflineSnapshot: vi.fn(),
}));

vi.mock('@/services/vaultRecoveryService', () => ({
  resetUserVaultState: vi.fn(),
}));

vi.mock('@/services/vaultIntegrityV2/productItemEnvelope', () => ({
  decryptProductVaultItem: (input: { encryptedData: string; vaultKey: CryptoKey; entryId: string }) =>
    cryptoMocks.decryptVaultItem(input.encryptedData, input.vaultKey, input.entryId),
  decryptProductVaultItemForMigration: (input: { encryptedData: string; vaultKey: CryptoKey; entryId: string }) =>
    cryptoMocks.decryptVaultItemForMigration(input.encryptedData, input.vaultKey, input.entryId),
  encryptProductVaultItemV2: (input: { data: unknown; vaultKey: CryptoKey; entryId: string }) =>
    cryptoMocks.encryptVaultItem(input.data, input.vaultKey, input.entryId),
}));

import { restoreQuarantinedVaultItem } from './vaultRecoveryOrchestrator';

describe('vaultRecoveryOrchestrator', () => {
  const trustedItem = {
    id: 'item-1',
    user_id: 'user-1',
    vault_id: 'vault-1',
    title: 'Legacy title',
    website_url: 'https://example.com',
    icon_url: null,
    item_type: 'password',
    is_favorite: true,
    encrypted_data: 'legacy-cipher',
    category_id: 'cat-1',
    sort_order: null,
    last_used_at: null,
    created_at: '2026-04-01T00:00:00.000Z',
    updated_at: '2026-04-01T00:00:00.000Z',
  } as const;

  beforeEach(() => {
    vi.clearAllMocks();
    cryptoMocks.decryptVaultItemForMigration.mockResolvedValue({
      data: { password: 'secret' },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: true,
    });
    cryptoMocks.encryptVaultItem.mockResolvedValue('aad-bound-cipher');
    recoveryMocks.restoreQuarantinedItemFromTrustedSnapshot.mockResolvedValue({ syncedOnline: true });
  });

  it('rebinds a trusted legacy no-AAD recovery copy before confirming quarantine removal', async () => {
    const verifyIntegrity = vi.fn().mockResolvedValue({ quarantinedItems: [] });
    const refreshIntegrityBaseline = vi.fn().mockResolvedValue(undefined);

    await restoreQuarantinedVaultItem({
      userId: 'user-1',
      itemId: 'item-1',
      activeKey: {} as CryptoKey,
      trustedSnapshotItem: trustedItem,
      refreshIntegrityBaseline,
      verifyIntegrity,
    });

    expect(cryptoMocks.encryptVaultItem).toHaveBeenCalledWith(
      expect.objectContaining({
        password: 'secret',
        title: 'Legacy title',
        websiteUrl: 'https://example.com',
        isFavorite: true,
        categoryId: 'cat-1',
      }),
      {},
      'item-1',
    );
    expect(recoveryMocks.restoreQuarantinedItemFromTrustedSnapshot).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({
        id: 'item-1',
        encrypted_data: 'aad-bound-cipher',
      }),
    );
    expect(refreshIntegrityBaseline).toHaveBeenCalledWith({ itemIds: ['item-1'] });
    expect(verifyIntegrity).toHaveBeenCalled();
  });

  it('refreshes the trusted baseline before confirming restored item integrity', async () => {
    const calls: string[] = [];
    const refreshIntegrityBaseline = vi.fn().mockImplementation(async () => {
      calls.push('refresh');
    });
    const verifyIntegrity = vi.fn().mockImplementation(async () => {
      calls.push('verify');
      return { quarantinedItems: [] };
    });

    await restoreQuarantinedVaultItem({
      userId: 'user-1',
      itemId: 'item-1',
      activeKey: {} as CryptoKey,
      trustedSnapshotItem: trustedItem,
      refreshIntegrityBaseline,
      verifyIntegrity,
    });

    expect(calls).toEqual(['refresh', 'verify']);
  });

  it('rewraps legacy AAD-bound recovery copies into the current vault item envelope', async () => {
    cryptoMocks.decryptVaultItemForMigration.mockResolvedValue({
      data: { password: 'secret' },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: false,
    });
    const verifyIntegrity = vi.fn().mockResolvedValue({ quarantinedItems: [] });
    const refreshIntegrityBaseline = vi.fn().mockResolvedValue(undefined);

    await restoreQuarantinedVaultItem({
      userId: 'user-1',
      itemId: 'item-1',
      activeKey: {} as CryptoKey,
      trustedSnapshotItem: {
        ...trustedItem,
        title: 'Encrypted Item',
        website_url: null,
        is_favorite: false,
        category_id: null,
      },
      refreshIntegrityBaseline,
      verifyIntegrity,
    });

    expect(cryptoMocks.encryptVaultItem).toHaveBeenCalledWith(
      expect.objectContaining({ password: 'secret' }),
      {},
      'item-1',
    );
    expect(recoveryMocks.restoreQuarantinedItemFromTrustedSnapshot).toHaveBeenCalledWith(
      'user-1',
      expect.objectContaining({ encrypted_data: 'aad-bound-cipher' }),
    );
  });
});
