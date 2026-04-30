import { beforeEach, describe, expect, it, vi } from 'vitest';

const cryptoMocks = vi.hoisted(() => ({
  CURRENT_KDF_VERSION: 2,
  KDF_PARAMS: {
    1: { memory: 65536, iterations: 3, parallelism: 4, hashLength: 32 },
    2: { memory: 131072, iterations: 3, parallelism: 4, hashLength: 32 },
  },
  createVerificationHash: vi.fn(async () => 'master-only-verifier'),
  deriveRawKey: vi.fn(async (_password: string, _salt: string, _version: number, deviceKey?: Uint8Array) =>
    deviceKey ? new Uint8Array(32).fill(4) : new Uint8Array(32).fill(1)),
  rewrapUserKey: vi.fn(async () => 'master-only-encrypted-user-key'),
  unwrapUserKey: vi.fn(async () => ({ kind: 'user-key' })),
}));

const deviceKeyServiceMocks = vi.hoisted(() => ({
  deleteDeviceKey: vi.fn(async () => undefined),
  getDeviceKey: vi.fn(async () => new Uint8Array(32).fill(9)),
  hasDeviceKey: vi.fn(async () => true),
}));

const nativeBridgeMocks = vi.hoisted(() => ({
  deriveNativeDeviceProtectedKey: vi.fn(async () => new Uint8Array(32).fill(7)),
  isNativeDeviceKeyBridgeRuntime: vi.fn(() => true),
}));

const twoFactorMocks = vi.hoisted(() => ({
  get2FAStatus: vi.fn(async () => ({
    isEnabled: true,
    vaultTwoFactorEnabled: true,
    lastVerifiedAt: null,
    backupCodesRemaining: 5,
  })),
  verifyTwoFactorCode: vi.fn(async () => ({ success: true })),
}));

const offlineVaultMocks = vi.hoisted(() => ({
  saveOfflineCredentials: vi.fn(async () => undefined),
}));

const supabaseMock = vi.hoisted(() => {
  const profileUpdateChain: Record<string, unknown> = {};
  profileUpdateChain.update = vi.fn(() => profileUpdateChain);
  profileUpdateChain.eq = vi.fn(async () => ({ error: null }));
  return {
    from: vi.fn(() => profileUpdateChain),
    _profileUpdateChain: profileUpdateChain,
  };
});

vi.mock('@/services/cryptoService', () => cryptoMocks);
vi.mock('@/services/deviceKeyService', () => deviceKeyServiceMocks);
vi.mock('@/services/deviceKeyNativeBridge', () => nativeBridgeMocks);
vi.mock('@/services/twoFactorService', () => twoFactorMocks);
vi.mock('@/services/offlineVaultService', () => offlineVaultMocks);
vi.mock('@/integrations/supabase/client', () => ({ supabase: supabaseMock }));

describe('deviceKeyDeactivationService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    deviceKeyServiceMocks.hasDeviceKey.mockResolvedValue(true);
    deviceKeyServiceMocks.getDeviceKey.mockResolvedValue(new Uint8Array(32).fill(9));
    nativeBridgeMocks.isNativeDeviceKeyBridgeRuntime.mockReturnValue(true);
    nativeBridgeMocks.deriveNativeDeviceProtectedKey.mockResolvedValue(new Uint8Array(32).fill(7));
    twoFactorMocks.get2FAStatus.mockResolvedValue({
      isEnabled: true,
      vaultTwoFactorEnabled: true,
      lastVerifiedAt: null,
      backupCodesRemaining: 5,
    });
    twoFactorMocks.verifyTwoFactorCode.mockResolvedValue({ success: true });
    cryptoMocks.rewrapUserKey.mockResolvedValue('master-only-encrypted-user-key');
    supabaseMock._profileUpdateChain.eq.mockResolvedValue({ error: null });
  });

  it('rewraps a native Device-Key-protected UserKey to master-only before deleting the local key', async () => {
    const { deactivateDeviceKeyProtection } = await import('../deviceKeyDeactivationService');

    const result = await deactivateDeviceKeyProtection({
      userId: 'user-1',
      masterPassword: 'correct-password',
      salt: 'salt',
      kdfVersion: 2,
      encryptedUserKey: 'device-protected-user-key',
      currentDeviceKey: null,
      twoFactorCode: '123456',
    });

    expect(result.error).toBeNull();
    expect(twoFactorMocks.verifyTwoFactorCode).toHaveBeenCalledWith({
      userId: 'user-1',
      context: 'critical_action',
      code: '123456',
      method: 'totp',
    });
    expect(nativeBridgeMocks.deriveNativeDeviceProtectedKey).toHaveBeenCalledWith('user-1', expect.any(Uint8Array));
    expect(cryptoMocks.rewrapUserKey).toHaveBeenCalledWith(
      'device-protected-user-key',
      expect.any(Uint8Array),
      expect.any(Uint8Array),
    );
    expect(supabaseMock._profileUpdateChain.update).toHaveBeenCalledWith(expect.objectContaining({
      encrypted_user_key: 'master-only-encrypted-user-key',
      vault_protection_mode: 'master_only',
      device_key_version: null,
      device_key_enabled_at: null,
      device_key_backup_acknowledged_at: null,
    }));
    expect(offlineVaultMocks.saveOfflineCredentials).toHaveBeenCalledWith(
      'user-1',
      'salt',
      'master-only-verifier',
      2,
      'master-only-encrypted-user-key',
      'master_only',
    );
    expect(deviceKeyServiceMocks.deleteDeviceKey).toHaveBeenCalledWith('user-1');
    expect(result.state).toMatchObject({
      encryptedUserKey: 'master-only-encrypted-user-key',
      verificationHash: 'master-only-verifier',
      currentDeviceKey: null,
      deviceKeyActive: false,
      kdfVersion: 2,
      vaultProtectionMode: 'master_only',
    });
  });

  it('does not persist anything when the local Device Key is missing', async () => {
    const { deactivateDeviceKeyProtection } = await import('../deviceKeyDeactivationService');
    deviceKeyServiceMocks.hasDeviceKey.mockResolvedValue(false);

    const result = await deactivateDeviceKeyProtection({
      userId: 'user-1',
      masterPassword: 'correct-password',
      salt: 'salt',
      kdfVersion: 2,
      encryptedUserKey: 'device-protected-user-key',
      currentDeviceKey: null,
      twoFactorCode: '123456',
    });

    expect(result.error).toMatchObject({ code: 'DEVICE_KEY_REQUIRED_BUT_MISSING' });
    expect(supabaseMock._profileUpdateChain.update).not.toHaveBeenCalled();
    expect(deviceKeyServiceMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });

  it('requires a current TOTP code when vault 2FA is enabled', async () => {
    const { deactivateDeviceKeyProtection } = await import('../deviceKeyDeactivationService');

    const result = await deactivateDeviceKeyProtection({
      userId: 'user-1',
      masterPassword: 'correct-password',
      salt: 'salt',
      kdfVersion: 2,
      encryptedUserKey: 'device-protected-user-key',
      currentDeviceKey: null,
      twoFactorCode: '',
    });

    expect(result.error).toMatchObject({ name: 'DeviceKeyDeactivationError', code: 'TWO_FACTOR_REQUIRED' });
    expect(twoFactorMocks.verifyTwoFactorCode).not.toHaveBeenCalled();
    expect(supabaseMock._profileUpdateChain.update).not.toHaveBeenCalled();
    expect(deviceKeyServiceMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });

  it('does not delete the local Device Key when profile persistence fails', async () => {
    const { deactivateDeviceKeyProtection } = await import('../deviceKeyDeactivationService');
    supabaseMock._profileUpdateChain.eq.mockResolvedValue({ error: { message: 'RLS rejected update' } });

    const result = await deactivateDeviceKeyProtection({
      userId: 'user-1',
      masterPassword: 'correct-password',
      salt: 'salt',
      kdfVersion: 2,
      encryptedUserKey: 'device-protected-user-key',
      currentDeviceKey: null,
      twoFactorCode: '123456',
    });

    expect(result.error).toMatchObject({ name: 'DeviceKeyDeactivationError', code: 'PROFILE_PERSIST_FAILED' });
    expect(deviceKeyServiceMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });

  it('uses the browser Device Key bytes instead of exporting native key material', async () => {
    const { deactivateDeviceKeyProtection } = await import('../deviceKeyDeactivationService');
    nativeBridgeMocks.isNativeDeviceKeyBridgeRuntime.mockReturnValue(false);
    twoFactorMocks.get2FAStatus.mockResolvedValue({
      isEnabled: false,
      vaultTwoFactorEnabled: false,
      lastVerifiedAt: null,
      backupCodesRemaining: 0,
    });
    const localDeviceKey = new Uint8Array(32).fill(8);

    const result = await deactivateDeviceKeyProtection({
      userId: 'user-1',
      masterPassword: 'correct-password',
      salt: 'salt',
      kdfVersion: 2,
      encryptedUserKey: 'device-protected-user-key',
      currentDeviceKey: localDeviceKey,
    });

    expect(result.error).toBeNull();
    expect(cryptoMocks.deriveRawKey).toHaveBeenCalledWith('correct-password', 'salt', 2, localDeviceKey);
    expect(nativeBridgeMocks.deriveNativeDeviceProtectedKey).not.toHaveBeenCalled();
    expect(twoFactorMocks.verifyTwoFactorCode).not.toHaveBeenCalled();
  });
});
