import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let index = 0;

  function createChain(resolved: unknown = { data: null, error: null }) {
    const chain: Record<string, unknown> = {};
    for (const method of ['select', 'update', 'eq', 'order', 'limit']) {
      chain[method] = vi.fn(() => chain);
    }
    chain.then = (resolve: (value: unknown) => unknown) => resolve(resolved);
    return chain;
  }

  return {
    from: vi.fn(() => chains[index++] ?? createChain()),
    _createChain: createChain,
    _setChains: (next: unknown[]) => {
      chains.length = 0;
      chains.push(...next);
      index = 0;
    },
  };
});

const cryptoMocks = vi.hoisted(() => ({
  decryptVaultItem: vi.fn(),
  decrypt: vi.fn(),
  deriveKey: vi.fn(),
  reEncryptVault: vi.fn(),
}));

vi.mock('@/integrations/supabase/client', () => ({ supabase: mockSupabase }));
vi.mock('@/platform/tauriDevMode', () => ({ isTauriDevUserId: () => false }));
vi.mock('@/services/cryptoService', () => cryptoMocks);

describe('vaultKdfRepairService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cryptoMocks.decrypt.mockResolvedValue('category');
    cryptoMocks.deriveKey.mockResolvedValue({ kind: 'old-key' });
    cryptoMocks.decryptVaultItem.mockImplementation(async (_cipher: string, key: unknown) => {
      if (key === activeKey) {
        throw new Error('active key cannot decrypt legacy row');
      }
      return { title: 'legacy row' };
    });
    cryptoMocks.reEncryptVault.mockResolvedValue({
      itemsReEncrypted: 1,
      categoriesReEncrypted: 0,
      itemUpdates: [{ id: 'item-1', encrypted_data: 'new-cipher' }],
      categoryUpdates: [],
    });
  });

  const activeKey = { kind: 'active-key' } as CryptoKey;

  it('skips the online repair probe while the app is offline', async () => {
    const { repairBrokenKdfUpgradeIfNeeded } = await import('../vaultKdfRepairService');
    const onlineSpy = vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    await repairBrokenKdfUpgradeIfNeeded({
      userId: 'user-1',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      activeKey,
    });

    expect(mockSupabase.from).not.toHaveBeenCalled();
    expect(infoSpy).toHaveBeenCalledWith(
      'KDF repair check skipped while offline.',
      expect.objectContaining({ code: 'network_unavailable' }),
    );
    expect(errorSpy).not.toHaveBeenCalled();

    onlineSpy.mockRestore();
    infoSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('propagates failed item updates as retryable KDF repair persistence errors', async () => {
    const { KdfRepairPersistenceError, repairBrokenKdfUpgradeIfNeeded } = await import('../vaultKdfRepairService');

    mockSupabase._setChains([
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: null, error: { message: 'RLS rejected update', code: '42501' } }),
    ]);

    const repair = repairBrokenKdfUpgradeIfNeeded({
      userId: 'user-1',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      activeKey,
    });

    await expect(repair).rejects.toMatchObject({
      name: 'KdfRepairPersistenceError',
      rowKind: 'vault_item',
      rowId: 'item-1',
    });
    await repair.catch((error) => {
      expect(error).toBeInstanceOf(KdfRepairPersistenceError);
    });
  });

  it('does not report repair completion when a row update fails', async () => {
    const { repairBrokenKdfUpgradeIfNeeded } = await import('../vaultKdfRepairService');
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);

    mockSupabase._setChains([
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: null, error: { message: 'connection reset' } }),
    ]);

    await expect(repairBrokenKdfUpgradeIfNeeded({
      userId: 'user-1',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      activeKey,
    })).rejects.toThrow(/Repair is incomplete and retryable/);

    expect(infoSpy).not.toHaveBeenCalledWith(expect.stringContaining('KDF repair complete'));
    infoSpy.mockRestore();
  });
});
