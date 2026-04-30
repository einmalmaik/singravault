import {
  importMasterKey,
  unwrapUserKey,
  unwrapUserKeyBytes,
  verifyKey,
} from '@/services/cryptoService';
import { authenticatePasskey } from '@/services/passkeyService';
import { isAppOnline } from '@/services/offlineVaultService';
import { getUnlockCooldown, recordFailedAttempt, resetUnlockAttempts } from '@/services/rateLimiterService';
import type { RequiredDeviceKeyResult } from '@/services/deviceKeyUnlockOrchestrator';
import {
  backfillVerificationHashForVault,
  migrateLegacyVaultToUserKey,
  recoverLegacyUserKeyWithoutVerifier,
} from '@/services/vaultUserKeyMigrationService';
import type { VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';

export interface VaultUnlockOptions {
  verifyTwoFactor?: () => Promise<boolean>;
}

export interface VaultPasskeyUnlockInput {
  userId: string;
  salt: string | null;
  kdfVersion: number;
  verificationHash: string | null;
  encryptedUserKey: string | null;
  vaultProtectionMode: VaultProtectionMode;
  options?: VaultUnlockOptions;
  getRequiredDeviceKey: () => Promise<RequiredDeviceKeyResult>;
  enforceVaultTwoFactorBeforeKeyRelease: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
  finalizeVaultUnlock: (activeKey: CryptoKey) => Promise<{ error: Error | null }>;
  applyCredentialUpdates: (updates: {
    verificationHash?: string;
    encryptedUserKey?: string | null;
  }) => Promise<void> | void;
}

export async function unlockVaultWithPasskey(
  input: VaultPasskeyUnlockInput,
): Promise<{ error: Error | null }> {
  const cooldown = getUnlockCooldown();
  if (cooldown !== null) {
    const seconds = Math.ceil(cooldown / 1000);
    return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
  }

  if (!isAppOnline()) {
    return {
      error: new Error(
        'Passkey unlock requires an online WebAuthn challenge. Use your master password for offline unlock.',
      ),
    };
  }

  try {
    // Passkey proves user presence/authentication only. It must not replace
    // local Device Key possession when the server-visible vault policy requires it.
    const { error: deviceKeyError } = await input.getRequiredDeviceKey();
    if (deviceKeyError) {
      return { error: deviceKeyError };
    }

    const result = await authenticatePasskey({ encryptedUserKey: input.encryptedUserKey });
    if (!result.success) {
      if (result.error === 'CANCELLED') {
        return { error: new Error('Passkey authentication was cancelled') };
      }
      if (result.error === 'NO_PRF') {
        return { error: new Error('This passkey does not support vault unlock (no PRF)') };
      }
      recordFailedAttempt();
      return { error: new Error(result.error || 'Passkey authentication failed') };
    }

    if (!result.encryptionKey) {
      recordFailedAttempt();
      return { error: new Error('Passkey authenticated but no encryption key derived') };
    }

    let activeKey = result.encryptionKey;
    let shouldBackfillVerifier = !input.verificationHash;
    if (input.verificationHash) {
      const isValid = await verifyKey(input.verificationHash, activeKey);
      if (!isValid) {
        recordFailedAttempt();
        return { error: new Error('Passkey-derived key does not match vault - key may be outdated') };
      }
    } else if (input.encryptedUserKey || result.keySource === 'vault-key') {
      shouldBackfillVerifier = true;
    } else {
      const isValid = await recoverLegacyUserKeyWithoutVerifier({
        userId: input.userId,
        candidateKey: activeKey,
      });
      if (!isValid) {
        recordFailedAttempt();
        return { error: new Error('Passkey-derived key does not match vault - key may be outdated') };
      }
    }

    if (!input.encryptedUserKey && result.keySource === 'legacy-kdf' && result.legacyKdfOutputBytes) {
      try {
        const migration = await migrateLegacyVaultToUserKey({
          userId: input.userId,
          salt: input.salt ?? '',
          kdfVersion: input.kdfVersion,
          vaultProtectionMode: input.vaultProtectionMode,
          kdfOutputBytes: result.legacyKdfOutputBytes,
        });
        activeKey = migration.userKey;
        await input.applyCredentialUpdates({
          verificationHash: migration.verifier,
          encryptedUserKey: migration.encryptedUserKey,
        });
        shouldBackfillVerifier = false;
      } finally {
        result.legacyKdfOutputBytes.fill(0);
      }
    } else {
      result.legacyKdfOutputBytes?.fill(0);
    }

    resetUnlockAttempts();
    const twoFactorResult = await input.enforceVaultTwoFactorBeforeKeyRelease(input.options);
    if (twoFactorResult.error) {
      return twoFactorResult;
    }

    const finalizeResult = await input.finalizeVaultUnlock(activeKey);
    if (finalizeResult.error) {
      return finalizeResult;
    }

    if (shouldBackfillVerifier && input.salt) {
      const verifier = await backfillVerificationHashForVault({
        userId: input.userId,
        salt: input.salt,
        kdfVersion: input.kdfVersion,
        encryptedUserKey: input.encryptedUserKey,
        vaultProtectionMode: input.vaultProtectionMode,
        activeKey,
      });
      if (verifier) {
        await input.applyCredentialUpdates({ verificationHash: verifier });
      }
    }

    return { error: null };
  } catch (error) {
    console.error('Passkey unlock error:', error);
    recordFailedAttempt();
    return { error: new Error('Passkey unlock failed') };
  }
}

export async function getPasskeyWrappingMaterialForVault(input: {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  verificationHash: string | null;
  encryptedUserKey: string | null;
  getRequiredDeviceKey: () => Promise<RequiredDeviceKeyResult>;
  deriveVaultKdfOutput: (
    masterPassword: string,
    deviceKey: Uint8Array | null,
    deviceKeyAvailable: boolean,
  ) => Promise<Uint8Array>;
}): Promise<Uint8Array | null> {
  let kdfOutputBytes: Uint8Array | null = null;
  try {
    const { deviceKey, deviceKeyAvailable, error: deviceKeyError } = await input.getRequiredDeviceKey();
    if (deviceKeyError) {
      console.warn('Failed to derive passkey wrapping material:', deviceKeyError);
      return null;
    }
    kdfOutputBytes = await input.deriveVaultKdfOutput(
      input.masterPassword,
      deviceKey,
      deviceKeyAvailable,
    );

    if (input.encryptedUserKey) {
      const userKey = await unwrapUserKey(input.encryptedUserKey, kdfOutputBytes);
      if (input.verificationHash) {
        const isValid = await verifyKey(input.verificationHash, userKey);
        if (!isValid) {
          return null;
        }
      }

      return unwrapUserKeyBytes(input.encryptedUserKey, kdfOutputBytes);
    }

    const derivedKey = await importMasterKey(kdfOutputBytes);
    if (input.verificationHash) {
      const isValid = await verifyKey(input.verificationHash, derivedKey);
      if (!isValid) {
        return null;
      }
    } else {
      const recovered = await recoverLegacyUserKeyWithoutVerifier({
        userId: input.userId,
        candidateKey: derivedKey,
      });
      if (!recovered) {
        return null;
      }
    }

    const wrappingMaterial = kdfOutputBytes;
    kdfOutputBytes = null;
    return wrappingMaterial;
  } catch (error) {
    console.error('Failed to derive passkey wrapping material:', error);
    return null;
  } finally {
    kdfOutputBytes?.fill(0);
  }
}
