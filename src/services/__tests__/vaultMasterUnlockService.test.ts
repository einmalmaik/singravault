import { beforeEach, describe, expect, it, vi } from 'vitest';
import { unlockVaultWithMasterPassword } from '../vaultMasterUnlockService';
import { createDeviceKeyMissingError } from '../deviceKeyProtectionPolicy';

const mockAttemptDualUnlock = vi.fn();
const mockGetUnlockCooldown = vi.fn(() => null);
const mockRecordFailedAttempt = vi.fn();
const mockResetUnlockAttempts = vi.fn();

vi.mock('@/extensions/registry', () => ({
  getServiceHooks: () => ({ attemptDualUnlock: mockAttemptDualUnlock }),
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
});
