import { beforeEach, describe, expect, it, vi } from 'vitest';

const offlineVaultServiceMock = vi.hoisted(() => ({
  fetchRemoteOfflineSnapshot: vi.fn(),
  getOfflineCredentials: vi.fn(),
  getOfflineSnapshot: vi.fn(),
  isAppOnline: vi.fn(() => true),
  isLikelyOfflineError: vi.fn(() => false),
  loadVaultSnapshot: vi.fn(),
  saveOfflineSnapshot: vi.fn(),
}));

const supabaseMock = vi.hoisted(() => ({
  from: vi.fn(),
}));

vi.mock('../offlineVaultService', () => offlineVaultServiceMock);
vi.mock('@/integrations/supabase/client', () => ({ supabase: supabaseMock }));

function createProfileChain(profile: Record<string, unknown>) {
  const chain: Record<string, unknown> = {};
  chain.select = vi.fn(() => chain);
  chain.eq = vi.fn(() => chain);
  chain.maybeSingle = vi.fn(async () => ({ data: profile, error: null }));
  return chain;
}

describe('offlineVaultRuntimeService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    offlineVaultServiceMock.getOfflineCredentials.mockResolvedValue(null);
    offlineVaultServiceMock.isAppOnline.mockReturnValue(true);
  });

  it('treats the remote profile as authoritative when Device Key was disabled elsewhere', async () => {
    const { loadRemoteVaultProfile } = await import('../offlineVaultRuntimeService');
    supabaseMock.from.mockReturnValue(createProfileChain({
      encryption_salt: 'salt',
      master_password_verifier: 'verifier',
      kdf_version: 2,
      encrypted_user_key: 'wrapped-user-key',
      vault_protection_mode: 'master_only',
    }));
    offlineVaultServiceMock.getOfflineCredentials.mockResolvedValue({
      salt: 'salt',
      verifier: 'verifier',
      kdfVersion: 2,
      encryptedUserKey: 'wrapped-user-key',
      vaultProtectionMode: 'device_key_required',
    });

    await expect(loadRemoteVaultProfile('user-1')).resolves.toMatchObject({
      credentials: {
        vaultProtectionMode: 'master_only',
      },
    });
  });

  it('can prefer a remote integrity snapshot even when navigator state says offline', async () => {
    const { loadCurrentVaultIntegritySnapshot } = await import('../offlineVaultRuntimeService');
    const remoteSnapshot = {
      userId: 'user-1',
      vaultId: 'vault-1',
      items: [],
      categories: [],
    };
    offlineVaultServiceMock.isAppOnline.mockReturnValue(false);
    offlineVaultServiceMock.fetchRemoteOfflineSnapshot.mockResolvedValue(remoteSnapshot);

    await expect(loadCurrentVaultIntegritySnapshot({
      userId: 'user-1',
      preferRemote: true,
    })).resolves.toMatchObject({
      rawSnapshot: remoteSnapshot,
      source: 'remote',
    });
    expect(offlineVaultServiceMock.loadVaultSnapshot).not.toHaveBeenCalled();
  });

  it('falls back to the cached integrity snapshot when the preferred remote fetch is offline', async () => {
    const { loadCurrentVaultIntegritySnapshot } = await import('../offlineVaultRuntimeService');
    const cachedSnapshot = {
      userId: 'user-1',
      vaultId: 'vault-1',
      items: [],
      categories: [],
    };
    offlineVaultServiceMock.isAppOnline.mockReturnValue(false);
    offlineVaultServiceMock.isLikelyOfflineError.mockReturnValue(true);
    offlineVaultServiceMock.fetchRemoteOfflineSnapshot.mockRejectedValue(new Error('Failed to fetch'));
    offlineVaultServiceMock.loadVaultSnapshot.mockResolvedValue({
      snapshot: cachedSnapshot,
      source: 'cache',
    });

    await expect(loadCurrentVaultIntegritySnapshot({
      userId: 'user-1',
      preferRemote: true,
    })).resolves.toMatchObject({
      rawSnapshot: cachedSnapshot,
      source: 'cache',
    });
  });
});
