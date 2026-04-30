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
});
