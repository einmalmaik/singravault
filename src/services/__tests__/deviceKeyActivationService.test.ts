import { beforeEach, describe, expect, it, vi } from 'vitest';

const cryptoMocks = vi.hoisted(() => ({
  CURRENT_KDF_VERSION: 2,
  KDF_PARAMS: {
    1: { memory: 65536, iterations: 3, parallelism: 4, hashLength: 32 },
    2: { memory: 131072, iterations: 3, parallelism: 4, hashLength: 32 },
  },
  createVerificationHash: vi.fn(async () => 'new-verifier'),
  deriveKey: vi.fn(),
  deriveRawKey: vi.fn(async (_password: string, _salt: string, _version: number, deviceKey?: Uint8Array) =>
    deviceKey ? new Uint8Array(32).fill(2) : new Uint8Array(32).fill(1)),
  importMasterKey: vi.fn(),
  migrateToUserKey: vi.fn(async () => ({
    encryptedUserKey: 'recovered-migrated-user-key',
    userKey: { kind: 'recovered-user-key' },
  })),
  reEncryptVault: vi.fn(),
  rewrapUserKey: vi.fn(async () => 'new-encrypted-user-key'),
  unwrapUserKey: vi.fn(async () => ({ kind: 'user-key' })),
  verifyKey: vi.fn(async () => true),
}));

const deviceKeyServiceMocks = vi.hoisted(() => ({
  deleteDeviceKey: vi.fn(async () => undefined),
  generateDeviceKey: vi.fn(() => new Uint8Array(32).fill(7)),
  hasDeviceKey: vi.fn(async () => false),
  storeDeviceKey: vi.fn(async () => undefined),
}));

const nativeBridgeMocks = vi.hoisted(() => ({
  DeviceKeyNativeError: class DeviceKeyNativeError extends Error {
    constructor(public readonly code: string) {
      super(code);
      this.name = 'DeviceKeyNativeError';
    }
  },
  deriveNativeDeviceProtectedKey: vi.fn(async () => new Uint8Array(32).fill(3)),
  generateAndStoreNativeDeviceKey: vi.fn(async () => undefined),
  isNativeDeviceKeyBridgeRuntime: vi.fn(() => true),
}));

const offlineVaultServiceMocks = vi.hoisted(() => ({
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
vi.mock('@/platform/localSecretStore', () => ({ isLocalSecretStoreSupported: vi.fn(async () => true) }));
vi.mock('@/services/offlineVaultService', () => offlineVaultServiceMocks);
vi.mock('@/integrations/supabase/client', () => ({ supabase: supabaseMock }));

describe('deviceKeyActivationService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    deviceKeyServiceMocks.hasDeviceKey.mockResolvedValue(false);
    nativeBridgeMocks.isNativeDeviceKeyBridgeRuntime.mockReturnValue(true);
    nativeBridgeMocks.deriveNativeDeviceProtectedKey.mockResolvedValue(new Uint8Array(32).fill(3));
    cryptoMocks.rewrapUserKey.mockResolvedValue('new-encrypted-user-key');
    cryptoMocks.migrateToUserKey.mockResolvedValue({
      encryptedUserKey: 'recovered-migrated-user-key',
      userKey: { kind: 'recovered-user-key' },
    });
    cryptoMocks.verifyKey.mockResolvedValue(true);
    offlineVaultServiceMocks.saveOfflineCredentials.mockResolvedValue(undefined);
  });

  it('provisions and validates a native Device Key before marking the vault protected', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toBeNull();
    expect(nativeBridgeMocks.generateAndStoreNativeDeviceKey).toHaveBeenCalledWith('00000000-0000-4000-8000-000000000001');
    expect(nativeBridgeMocks.deriveNativeDeviceProtectedKey).toHaveBeenCalledTimes(2);
    expect(supabaseMock._profileUpdateChain.update).toHaveBeenCalledWith(expect.objectContaining({
      kdf_version: 2,
      vault_protection_mode: 'device_key_required',
      encrypted_user_key: 'new-encrypted-user-key',
    }));
    expect(result.state).toMatchObject({
      encryptedUserKey: 'new-encrypted-user-key',
      deviceKeyActive: true,
      kdfVersion: 2,
      vaultProtectionMode: 'device_key_required',
    });
  });

  it('does not mark native protection active when generated key readback still fails', async () => {
    const { DeviceKeyNativeError } = await import('../deviceKeyNativeBridge');
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    nativeBridgeMocks.deriveNativeDeviceProtectedKey.mockRejectedValue(new DeviceKeyNativeError('DEVICE_KEY_MISSING'));

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toMatchObject({ code: 'DEVICE_KEY_MISSING' });
    expect(deviceKeyServiceMocks.deleteDeviceKey).toHaveBeenCalledWith('00000000-0000-4000-8000-000000000001');
    expect(supabaseMock._profileUpdateChain.update).not.toHaveBeenCalled();
    expect(result.state).toBeUndefined();
  });

  it('keeps the native Device Key when offline credential persistence fails after profile commit', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    offlineVaultServiceMocks.saveOfflineCredentials.mockRejectedValue(new Error('IndexedDB unavailable'));

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toBeNull();
    expect(supabaseMock._profileUpdateChain.update).toHaveBeenCalledWith(expect.objectContaining({
      vault_protection_mode: 'device_key_required',
      encrypted_user_key: 'new-encrypted-user-key',
    }));
    expect(offlineVaultServiceMocks.saveOfflineCredentials).toHaveBeenCalled();
    expect(deviceKeyServiceMocks.deleteDeviceKey).not.toHaveBeenCalled();
    expect(result.state).toMatchObject({
      deviceKeyActive: true,
      vaultProtectionMode: 'device_key_required',
    });
  });

  it('tries older KDF versions when the stored UserKey wrapper metadata is stale', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    cryptoMocks.rewrapUserKey
      .mockRejectedValueOnce(new DOMException('decrypt failed', 'OperationError'))
      .mockResolvedValueOnce('new-encrypted-user-key');

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toBeNull();
    expect(cryptoMocks.deriveRawKey).toHaveBeenCalledWith('not-logged', 'salt', 2);
    expect(cryptoMocks.deriveRawKey).toHaveBeenCalledWith('not-logged', 'salt', 1, undefined);
    expect(cryptoMocks.rewrapUserKey).toHaveBeenCalledTimes(2);
  });

  it('tries the current KDF version when profile metadata is stale below the wrapper version', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    cryptoMocks.rewrapUserKey
      .mockRejectedValueOnce(new DOMException('decrypt failed', 'OperationError'))
      .mockResolvedValueOnce('new-encrypted-user-key');

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 1,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toBeNull();
    expect(cryptoMocks.deriveRawKey).toHaveBeenCalledWith('not-logged', 'salt', 1, undefined);
    expect(cryptoMocks.deriveRawKey).toHaveBeenCalledWith('not-logged', 'salt', 2, undefined);
    expect(supabaseMock._profileUpdateChain.update).toHaveBeenCalledWith(expect.objectContaining({
      kdf_version: 2,
      vault_protection_mode: 'device_key_required',
      encrypted_user_key: 'new-encrypted-user-key',
    }));
    expect(result.state).toMatchObject({
      kdfVersion: 2,
      vaultProtectionMode: 'device_key_required',
    });
  });

  it('does not mask unexpected UserKey rewrap errors as stale KDF metadata', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    cryptoMocks.rewrapUserKey.mockRejectedValue(new Error('invalid encrypted_user_key envelope'));

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 2,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'old-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toMatchObject({ message: 'invalid encrypted_user_key envelope' });
    expect(cryptoMocks.rewrapUserKey).toHaveBeenCalledTimes(1);
    expect(supabaseMock._profileUpdateChain.update).not.toHaveBeenCalled();
  });

  it('recovers deterministic migrated UserKey wrappers when persisted encrypted_user_key is stale', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    cryptoMocks.rewrapUserKey
      .mockRejectedValueOnce(new DOMException('decrypt failed', 'OperationError'))
      .mockRejectedValueOnce(new DOMException('decrypt failed', 'OperationError'))
      .mockResolvedValueOnce('new-encrypted-user-key');

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'not-logged',
      salt: 'salt',
      kdfVersion: 1,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'stale-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toBeNull();
    expect(cryptoMocks.migrateToUserKey).toHaveBeenCalled();
    expect(cryptoMocks.verifyKey).toHaveBeenCalledWith('current-verifier', { kind: 'recovered-user-key' });
    expect(cryptoMocks.rewrapUserKey).toHaveBeenLastCalledWith(
      'recovered-migrated-user-key',
      expect.any(Uint8Array),
      expect.any(Uint8Array),
    );
    expect(supabaseMock._profileUpdateChain.update).toHaveBeenCalledWith(expect.objectContaining({
      encrypted_user_key: 'new-encrypted-user-key',
      kdf_version: 2,
      vault_protection_mode: 'device_key_required',
    }));
  });

  it('does not recover stale wrappers when the entered master password does not match the verifier', async () => {
    const { activateDeviceKeyProtection } = await import('../deviceKeyActivationService');
    cryptoMocks.rewrapUserKey
      .mockRejectedValue(new DOMException('decrypt failed', 'OperationError'));
    cryptoMocks.verifyKey.mockResolvedValue(false);

    const result = await activateDeviceKeyProtection({
      userId: '00000000-0000-4000-8000-000000000001',
      masterPassword: 'wrong-password',
      salt: 'salt',
      kdfVersion: 1,
      encryptionKey: { kind: 'current-key' } as CryptoKey,
      encryptedUserKey: 'stale-encrypted-user-key',
      verificationHash: 'current-verifier',
      currentDeviceKey: null,
    });

    expect(result.error).toMatchObject({ name: 'DeviceKeyActivationRewrapError' });
    expect(supabaseMock._profileUpdateChain.update).not.toHaveBeenCalled();
  });
});
