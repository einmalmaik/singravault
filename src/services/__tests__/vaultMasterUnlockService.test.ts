import { beforeEach, describe, expect, it, vi } from 'vitest';
import { unlockVaultWithMasterPassword } from '../vaultMasterUnlockService';
import { createDeviceKeyMissingError } from '../deviceKeyProtectionPolicy';

const mockAttemptDualUnlock = vi.fn();
const mockAttemptDuressUnlockOnly = vi.fn();
const mockGetUnlockCooldown = vi.fn(() => null);
const mockRecordFailedAttempt = vi.fn();
const mockResetUnlockAttempts = vi.fn();
const mockImportMasterKey = vi.fn();
const mockUnwrapUserKeyBytes = vi.fn();
const mockVerifyKey = vi.fn();
const mockAttemptKdfUpgrade = vi.fn();
const mockRepairBrokenKdfUpgradeIfNeeded = vi.fn();
const mockMigrateLegacyPrivateKeys = vi.fn();

const mockHooks: {
  attemptDualUnlock?: typeof mockAttemptDualUnlock;
  attemptDuressUnlockOnly?: typeof mockAttemptDuressUnlockOnly;
} = {};

vi.mock('@/extensions/registry', () => ({
  getServiceHooks: () => mockHooks,
}));

vi.mock('@/services/cryptoService', () => ({
  attemptKdfUpgrade: (...args: unknown[]) => mockAttemptKdfUpgrade(...args),
  importMasterKey: (...args: unknown[]) => mockImportMasterKey(...args),
  unwrapUserKeyBytes: (...args: unknown[]) => mockUnwrapUserKeyBytes(...args),
  verifyKey: (...args: unknown[]) => mockVerifyKey(...args),
}));

vi.mock('@/services/vaultKdfRepairService', () => ({
  KdfRepairPersistenceError: class KdfRepairPersistenceError extends Error {},
  repairBrokenKdfUpgradeIfNeeded: (...args: unknown[]) => mockRepairBrokenKdfUpgradeIfNeeded(...args),
}));

vi.mock('@/services/vaultUserKeyMigrationService', () => ({
  backfillVerificationHashForVault: vi.fn(async () => null),
  migrateLegacyPrivateKeys: (...args: unknown[]) => mockMigrateLegacyPrivateKeys(...args),
  migrateLegacyVaultToUserKey: vi.fn(),
  recoverLegacyUserKeyWithoutVerifier: vi.fn(),
}));

vi.mock('@/services/offlineVaultService', () => ({
  saveOfflineCredentials: vi.fn(),
}));

vi.mock('@/services/deviceKeyNativeBridge', () => ({
  isNativeDeviceKeyBridgeRuntime: () => false,
}));

vi.mock('@/platform/tauriDevMode', () => ({
  isTauriDevUserId: () => false,
}));

vi.mock('@/services/rateLimiterService', () => ({
  getUnlockCooldown: () => mockGetUnlockCooldown(),
  recordFailedAttempt: () => mockRecordFailedAttempt(),
  resetUnlockAttempts: () => mockResetUnlockAttempts(),
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: { from: vi.fn() },
}));

describe('vaultMasterUnlockService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetUnlockCooldown.mockReturnValue(null);
    mockAttemptKdfUpgrade.mockResolvedValue({ upgraded: false });
    mockRepairBrokenKdfUpgradeIfNeeded.mockResolvedValue(undefined);
    mockMigrateLegacyPrivateKeys.mockResolvedValue(undefined);

    // Default: only the legacy dual-unlock hook is registered. Individual
    // tests reset this to opt into the new duress-only hook or remove hooks.
    delete mockHooks.attemptDualUnlock;
    delete mockHooks.attemptDuressUnlockOnly;
    mockHooks.attemptDualUnlock = mockAttemptDualUnlock;
  });

  it('does not run duress dual-unlock before Device Key enforcement for protected vaults', async () => {
    const deviceKeyError = createDeviceKeyMissingError();
    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'CorrectPassword!',
      salt: 'salt',
      verificationHash: 'verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'device_key_required',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: deviceKeyError,
      })),
      deriveVaultKdfOutput: vi.fn(),
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(),
      finalizeVaultUnlock: vi.fn(),
      openDuressVault: vi.fn(),
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBe(deviceKeyError);
    expect(mockAttemptDualUnlock).not.toHaveBeenCalled();
  });

  it('uses the primary unlock path for normal dual-unlock results so migration receives the vault key', async () => {
    const activeKey = { type: 'secret' } as CryptoKey;
    const kdfOutput = new Uint8Array([1, 2, 3, 4]);
    const vaultEncryptionKey = new Uint8Array([5, 6, 7, 8]);
    const deriveVaultKdfOutput = vi.fn(async () => new Uint8Array(kdfOutput));
    const finalizeVaultUnlock = vi.fn(async () => ({ error: null }));

    mockAttemptDualUnlock.mockResolvedValue({ mode: 'normal', key: activeKey });
    mockImportMasterKey.mockResolvedValue(activeKey);
    mockUnwrapUserKeyBytes.mockResolvedValue(new Uint8Array(vaultEncryptionKey));
    mockVerifyKey.mockResolvedValue(true);

    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'CorrectPassword!',
      salt: 'salt',
      verificationHash: 'verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput,
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock,
      openDuressVault: vi.fn(),
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBeNull();
    expect(mockAttemptDualUnlock).toHaveBeenCalled();
    expect(deriveVaultKdfOutput).toHaveBeenCalled();
    expect(finalizeVaultUnlock).toHaveBeenCalledWith(activeKey, expect.any(Uint8Array));
    expect(finalizeVaultUnlock.mock.calls[0]?.[1]).toEqual(vaultEncryptionKey);
    expect(result.vaultEncryptionKey).toEqual(vaultEncryptionKey);
  });

  it("falls back to the primary USK-based unlock when the legacy dual-unlock hook reports 'invalid' for a correct password", async () => {
    // Regression: pre-USK dual-unlock verifies the master password against the
    // master-derived key, but post-USK setups bind master_password_verifier to
    // the UserKey. The hook therefore returns mode='invalid' even when the
    // password is correct. The core must defer to the primary unlock path
    // (which uses the canonical USK-based verifier check) instead of failing.
    const activeKey = { type: 'secret' } as CryptoKey;
    const kdfOutput = new Uint8Array([1, 2, 3, 4]);
    const vaultEncryptionKey = new Uint8Array([5, 6, 7, 8]);
    const deriveVaultKdfOutput = vi.fn(async () => new Uint8Array(kdfOutput));
    const finalizeVaultUnlock = vi.fn(async () => ({ error: null }));

    mockAttemptDualUnlock.mockResolvedValue({ mode: 'invalid', key: null });
    mockImportMasterKey.mockResolvedValue(activeKey);
    mockUnwrapUserKeyBytes.mockResolvedValue(new Uint8Array(vaultEncryptionKey));
    mockVerifyKey.mockResolvedValue(true);

    const openDuressVault = vi.fn();
    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'CorrectPassword!',
      salt: 'salt',
      verificationHash: 'usk-bound-verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput,
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock,
      openDuressVault,
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBeNull();
    expect(mockAttemptDualUnlock).toHaveBeenCalledTimes(1);
    expect(deriveVaultKdfOutput).toHaveBeenCalled();
    expect(openDuressVault).not.toHaveBeenCalled();
    expect(finalizeVaultUnlock).toHaveBeenCalledWith(activeKey, expect.any(Uint8Array));
    expect(mockRecordFailedAttempt).not.toHaveBeenCalled();
  });

  it('falls back to the primary unlock path when the legacy dual-unlock hook throws', async () => {
    const activeKey = { type: 'secret' } as CryptoKey;
    const kdfOutput = new Uint8Array([1, 2, 3, 4]);
    const vaultEncryptionKey = new Uint8Array([5, 6, 7, 8]);
    const deriveVaultKdfOutput = vi.fn(async () => new Uint8Array(kdfOutput));
    const finalizeVaultUnlock = vi.fn(async () => ({ error: null }));

    mockAttemptDualUnlock.mockRejectedValue(new Error('premium duress hook crashed'));
    mockImportMasterKey.mockResolvedValue(activeKey);
    mockUnwrapUserKeyBytes.mockResolvedValue(new Uint8Array(vaultEncryptionKey));
    mockVerifyKey.mockResolvedValue(true);

    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'CorrectPassword!',
      salt: 'salt',
      verificationHash: 'usk-bound-verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput,
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock,
      openDuressVault: vi.fn(),
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBeNull();
    expect(finalizeVaultUnlock).toHaveBeenCalledWith(activeKey, expect.any(Uint8Array));
  });

  it("opens the duress vault via the dedicated duress-only hook when matched=true", async () => {
    const duressKey = { type: 'duress' } as CryptoKey;
    delete mockHooks.attemptDualUnlock;
    mockHooks.attemptDuressUnlockOnly = mockAttemptDuressUnlockOnly;
    mockAttemptDuressUnlockOnly.mockResolvedValue({ matched: true, key: duressKey });

    const openDuressVault = vi.fn();
    const deriveVaultKdfOutput = vi.fn();
    const finalizeVaultUnlock = vi.fn(async () => ({ error: null }));

    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'DuressPassword!',
      salt: 'salt',
      verificationHash: 'verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true, salt: 'duress-salt', verifier: 'dv', kdfVersion: 2 } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput,
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock,
      openDuressVault,
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBeNull();
    expect(mockAttemptDuressUnlockOnly).toHaveBeenCalledTimes(1);
    expect(openDuressVault).toHaveBeenCalledWith(duressKey);
    // Duress mode opens its own decoy vault and must not touch the primary
    // USK unlock path.
    expect(deriveVaultKdfOutput).not.toHaveBeenCalled();
    expect(finalizeVaultUnlock).not.toHaveBeenCalled();
  });

  it("falls through to the primary unlock when the duress-only hook reports matched=false", async () => {
    const activeKey = { type: 'secret' } as CryptoKey;
    const kdfOutput = new Uint8Array([1, 2, 3, 4]);
    const vaultEncryptionKey = new Uint8Array([5, 6, 7, 8]);
    delete mockHooks.attemptDualUnlock;
    mockHooks.attemptDuressUnlockOnly = mockAttemptDuressUnlockOnly;
    mockAttemptDuressUnlockOnly.mockResolvedValue({ matched: false, key: null });
    mockImportMasterKey.mockResolvedValue(activeKey);
    mockUnwrapUserKeyBytes.mockResolvedValue(new Uint8Array(vaultEncryptionKey));
    mockVerifyKey.mockResolvedValue(true);

    const finalizeVaultUnlock = vi.fn(async () => ({ error: null }));
    const result = await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'CorrectPassword!',
      salt: 'salt',
      verificationHash: 'usk-bound-verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true, salt: 'duress-salt', verifier: 'dv', kdfVersion: 2 } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput: vi.fn(async () => new Uint8Array(kdfOutput)),
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock,
      openDuressVault: vi.fn(),
      applyCredentialUpdates: vi.fn(),
    });

    expect(result.error).toBeNull();
    expect(finalizeVaultUnlock).toHaveBeenCalledWith(activeKey, expect.any(Uint8Array));
  });

  it('prefers the dedicated duress-only hook over the legacy dual-unlock hook when both are registered', async () => {
    const duressKey = { type: 'duress' } as CryptoKey;
    mockHooks.attemptDualUnlock = mockAttemptDualUnlock;
    mockHooks.attemptDuressUnlockOnly = mockAttemptDuressUnlockOnly;
    mockAttemptDuressUnlockOnly.mockResolvedValue({ matched: true, key: duressKey });

    const openDuressVault = vi.fn();
    await unlockVaultWithMasterPassword({
      userId: 'user-1',
      masterPassword: 'DuressPassword!',
      salt: 'salt',
      verificationHash: 'verifier',
      kdfVersion: 2,
      duressConfig: { enabled: true, salt: 'duress-salt', verifier: 'dv', kdfVersion: 2 } as never,
      encryptedUserKey: 'encrypted-user-key',
      vaultProtectionMode: 'master_only',
      getRequiredDeviceKey: vi.fn(async () => ({
        deviceKey: null,
        deviceKeyAvailable: false,
        error: null,
      })),
      deriveVaultKdfOutput: vi.fn(),
      enforceVaultTwoFactorBeforeKeyRelease: vi.fn(async () => ({ error: null })),
      finalizeVaultUnlock: vi.fn(async () => ({ error: null })),
      openDuressVault,
      applyCredentialUpdates: vi.fn(),
    });

    expect(mockAttemptDuressUnlockOnly).toHaveBeenCalled();
    expect(mockAttemptDualUnlock).not.toHaveBeenCalled();
    expect(openDuressVault).toHaveBeenCalledWith(duressKey);
  });
});
