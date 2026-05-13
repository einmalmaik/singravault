import { beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveVaultOpLogDefaultVaultId } from '../vaultOpLogDefaultVaultResolver';

const mocks = vi.hoisted(() => ({
  listVerifiedVaultOpLogOfflineCachesForUser: vi.fn(),
  isAppOnline: vi.fn(),
  resolveDefaultVaultId: vi.fn(),
  maybeSingle: vi.fn(),
}));

vi.mock('@/services/vaultOpLog/vaultOpLogOfflineStore', () => ({
  listVerifiedVaultOpLogOfflineCachesForUser: mocks.listVerifiedVaultOpLogOfflineCachesForUser,
}));

vi.mock('@/services/offlineVaultService', () => ({
  isAppOnline: mocks.isAppOnline,
  resolveDefaultVaultId: mocks.resolveDefaultVaultId,
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: {
    from: vi.fn(() => ({
      select: vi.fn(() => ({
        eq: vi.fn(() => ({
          eq: vi.fn(() => ({
            maybeSingle: mocks.maybeSingle,
          })),
        })),
      })),
    })),
  },
}));

describe('resolveVaultOpLogDefaultVaultId', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.isAppOnline.mockReturnValue(true);
    mocks.listVerifiedVaultOpLogOfflineCachesForUser.mockResolvedValue([]);
    mocks.resolveDefaultVaultId.mockResolvedValue(null);
    mocks.maybeSingle.mockResolvedValue({ data: { id: 'vault-online' }, error: null });
  });

  it('uses the online default vault row while online', async () => {
    await expect(resolveVaultOpLogDefaultVaultId('user-1')).resolves.toBe('vault-online');

    expect(mocks.maybeSingle).toHaveBeenCalledTimes(1);
    expect(mocks.listVerifiedVaultOpLogOfflineCachesForUser).not.toHaveBeenCalled();
  });

  it('uses the newest verified offline OpLog cache while offline', async () => {
    mocks.isAppOnline.mockReturnValue(false);
    mocks.listVerifiedVaultOpLogOfflineCachesForUser.mockResolvedValue([
      { vaultId: 'vault-offline-verified' },
    ]);

    await expect(resolveVaultOpLogDefaultVaultId('user-1')).resolves.toBe('vault-offline-verified');

    expect(mocks.maybeSingle).not.toHaveBeenCalled();
    expect(mocks.resolveDefaultVaultId).not.toHaveBeenCalled();
  });

  it('falls back to the legacy offline default vault id only for id discovery', async () => {
    mocks.isAppOnline.mockReturnValue(false);
    mocks.resolveDefaultVaultId.mockResolvedValue('vault-legacy-id');

    await expect(resolveVaultOpLogDefaultVaultId('user-1')).resolves.toBe('vault-legacy-id');

    expect(mocks.maybeSingle).not.toHaveBeenCalled();
  });
});
