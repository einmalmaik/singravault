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

  it('does not run legacy table repair writes after detecting broken legacy rows', async () => {
    const { repairBrokenKdfUpgradeIfNeeded } = await import('../vaultKdfRepairService');
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    mockSupabase._setChains([
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
    ]);

    await repairBrokenKdfUpgradeIfNeeded({
      userId: 'user-1',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      activeKey,
    });

    expect(cryptoMocks.reEncryptVault).not.toHaveBeenCalled();
    expect(warnSpy).toHaveBeenCalledWith(
      'KDF repair is blocked because legacy vault table writes are disabled.',
    );
    warnSpy.mockRestore();
  });

  it('does not report repair completion when legacy repair writes are blocked', async () => {
    const { repairBrokenKdfUpgradeIfNeeded } = await import('../vaultKdfRepairService');
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => undefined);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    mockSupabase._setChains([
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
      mockSupabase._createChain({ data: [{ id: 'item-1', encrypted_data: 'old-cipher' }], error: null }),
      mockSupabase._createChain({ data: [], error: null }),
    ]);

    await repairBrokenKdfUpgradeIfNeeded({
      userId: 'user-1',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      activeKey,
    });

    expect(infoSpy).not.toHaveBeenCalledWith(expect.stringContaining('KDF repair complete'));
    expect(warnSpy).toHaveBeenCalledWith(
      'KDF repair is blocked because legacy vault table writes are disabled.',
    );
    infoSpy.mockRestore();
    warnSpy.mockRestore();
  });
});
