import { beforeEach, describe, expect, it, vi } from 'vitest';
import { unlockVaultWithMasterPassword } from '../vaultMasterUnlockService';
import { createDeviceKeyMissingError } from '../deviceKeyProtectionPolicy';

const mockAttemptDualUnlock = vi.fn();
const mockGetUnlockCooldown = vi.fn(() => null);
const mockRecordFailedAttempt = vi.fn();
const mockResetUnlockAttempts = vi.fn();
const mockImportMasterKey = vi.fn();
const mockUnwrapUserKeyBytes = vi.fn();
const mockVerifyKey = vi.fn();
const mockAttemptKdfUpgrade = vi.fn();
const mockRepairBrokenKdfUpgradeIfNeeded = vi.fn();
const mockMigrateLegacyPrivateKeys = vi.fn();

vi.mock('@/extensions/registry', () => ({
  getServiceHooks: () => ({ attemptDualUnlock: mockAttemptDualUnlock }),
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
});
