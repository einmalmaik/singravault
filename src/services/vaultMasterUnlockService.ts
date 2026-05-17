import {
  attemptKdfUpgrade,
  importMasterKey,
  unwrapUserKeyBytes,
  verifyKey,
} from '@/services/cryptoService';
import {
  DeviceKeyUnlockError,
  createDeviceKeyInvalidError,
  createMasterPasswordInvalidError,
  requiresDeviceKey,
  type VaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import type { RequiredDeviceKeyResult } from '@/services/deviceKeyUnlockOrchestrator';
import { isNativeDeviceKeyBridgeRuntime } from '@/services/deviceKeyNativeBridge';
import { getServiceHooks } from '@/extensions/registry';
import type { DuressConfigHook } from '@/extensions/types';
import { getUnlockCooldown, recordFailedAttempt, resetUnlockAttempts } from '@/services/rateLimiterService';
import { saveOfflineCredentials } from '@/services/offlineVaultService';
import { supabase } from '@/integrations/supabase/client';
import { isTauriDevUserId } from '@/platform/tauriDevMode';
import {
  KdfRepairPersistenceError,
  repairBrokenKdfUpgradeIfNeeded,
} from '@/services/vaultKdfRepairService';
import {
  backfillVerificationHashForVault,
  migrateLegacyPrivateKeys,
  migrateLegacyVaultToUserKey,
  recoverLegacyUserKeyWithoutVerifier,
} from '@/services/vaultUserKeyMigrationService';

export interface VaultUnlockOptions {
  verifyTwoFactor?: () => Promise<boolean>;
}

export interface VaultMasterUnlockInput {
  userId: string;
  masterPassword: string;
  salt: string;
  verificationHash: string | null;
  kdfVersion: number;
  duressConfig: DuressConfigHook | null;
  encryptedUserKey: string | null;
  vaultProtectionMode: VaultProtectionMode;
  options?: VaultUnlockOptions;
  getRequiredDeviceKey: () => Promise<RequiredDeviceKeyResult>;
  deriveVaultKdfOutput: (
    masterPassword: string,
    deviceKey: Uint8Array | null,
    deviceKeyAvailable: boolean,
  ) => Promise<Uint8Array>;
  enforceVaultTwoFactorBeforeKeyRelease: (options?: VaultUnlockOptions) => Promise<{ error: Error | null }>;
  finalizeVaultUnlock: (activeKey: CryptoKey, vaultEncryptionKey?: Uint8Array) => Promise<{ error: Error | null }>;
  openDuressVault: (activeKey: CryptoKey) => void;
  applyCredentialUpdates: (updates: {
    verificationHash?: string;
    kdfVersion?: number;
    encryptedUserKey?: string | null;
  }) => Promise<void> | void;
}

export async function unlockVaultWithMasterPassword(
  input: VaultMasterUnlockInput,
): Promise<{ error: Error | null; vaultEncryptionKey?: Uint8Array }> {
  const cooldown = getUnlockCooldown();
  if (cooldown !== null) {
    const seconds = Math.ceil(cooldown / 1000);
    return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
  }

  try {
    // Duress/dual-unlock hooks derive alternate vault keys and are not
    // Device-Key-aware. Protected vaults must use the primary DK path only.
    if (!requiresDeviceKey(input.vaultProtectionMode)) {
      const duressResult = await tryDuressUnlock(input);
      if (duressResult.handled) {
        return { error: duressResult.error };
      }
    }

    return await unlockWithPrimaryVaultKey(input);
  } catch (error) {
    console.error('Error unlocking vault:', error);
    if (error instanceof DeviceKeyUnlockError) {
      return { error };
    }
    if (error instanceof KdfRepairPersistenceError) {
      return { error };
    }
    recordFailedAttempt();
    return {
      error: requiresDeviceKey(input.vaultProtectionMode)
        ? createDeviceKeyInvalidError()
        : createMasterPasswordInvalidError(),
    };
  }
}

async function tryDuressUnlock(
  input: VaultMasterUnlockInput,
): Promise<{ handled: boolean; error: Error | null }> {
  if (!input.duressConfig?.enabled) {
    return { handled: false, error: null };
  }

  const hooks = getServiceHooks();

  // Prefer the USK-safe duress-only hook. It verifies the duress credentials
  // in isolation and never touches the master-password verifier, so it stays
  // correct regardless of whether the verifier is bound to the master-derived
  // key (pre-USK) or the UserKey (post-USK).
  if (hooks.attemptDuressUnlockOnly) {
    return tryDuressUnlockViaDedicatedHook(input, hooks.attemptDuressUnlockOnly);
  }

  if (hooks.attemptDualUnlock) {
    return tryDuressUnlockViaLegacyDualHook(input, hooks.attemptDualUnlock);
  }

  return { handled: false, error: null };
}

async function tryDuressUnlockViaDedicatedHook(
  input: VaultMasterUnlockInput,
  hook: NonNullable<ReturnType<typeof getServiceHooks>['attemptDuressUnlockOnly']>,
): Promise<{ handled: boolean; error: Error | null }> {
  let result;
  try {
    result = await hook({
      password: input.masterPassword,
      duressConfig: input.duressConfig!,
    });
  } catch (error) {
    console.warn('Duress-only unlock hook threw; falling back to primary unlock.', error);
    return { handled: false, error: null };
  }

  if (!result.matched || !result.key) {
    // Duress did not match. The core's primary unlock path is the single
    // source of truth for the real master password and runs next.
    return { handled: false, error: null };
  }

  return openDuressVaultWithTwoFactor(input, result.key);
}

async function tryDuressUnlockViaLegacyDualHook(
  input: VaultMasterUnlockInput,
  hook: NonNullable<ReturnType<typeof getServiceHooks>['attemptDualUnlock']>,
): Promise<{ handled: boolean; error: Error | null }> {
  if (!input.verificationHash) {
    // Pre-USK dual-unlock requires a verifier; without one we cannot ask the
    // legacy hook, so defer to the primary path which has its own checks.
    return { handled: false, error: null };
  }

  let result;
  try {
    result = await hook(
      input.masterPassword,
      input.salt,
      input.verificationHash,
      input.kdfVersion,
      input.duressConfig!,
    );
  } catch (error) {
    console.warn('Legacy dual-unlock hook threw; falling back to primary unlock.', error);
    return { handled: false, error: null };
  }

  if (result.mode === 'duress' && result.key) {
    return openDuressVaultWithTwoFactor(input, result.key);
  }

  // For 'real', 'normal', 'invalid', or any unknown mode: defer to the primary
  // master-unlock path. Treating 'invalid' as terminal here would break unlock
  // for any USK-based vault: the legacy hook verifies against the
  // master-derived key, but `profiles.master_password_verifier` is bound to
  // the UserKey on post-USK setups, so `verifyKey` returns false even when
  // the password is correct. The primary path performs the canonical
  // USK-based verification and is authoritative.
  return { handled: false, error: null };
}

async function openDuressVaultWithTwoFactor(
  input: VaultMasterUnlockInput,
  duressKey: CryptoKey,
): Promise<{ handled: boolean; error: Error | null }> {
  resetUnlockAttempts();
  const twoFactorResult = await input.enforceVaultTwoFactorBeforeKeyRelease(input.options);
  if (twoFactorResult.error) {
    return { handled: true, error: twoFactorResult.error };
  }
  input.openDuressVault(duressKey);
  return { handled: true, error: null };
}

async function unlockWithPrimaryVaultKey(
  input: VaultMasterUnlockInput,
): Promise<{ error: Error | null; vaultEncryptionKey?: Uint8Array }> {
  const { deviceKey, deviceKeyAvailable, error: deviceKeyError } = await input.getRequiredDeviceKey();
  if (deviceKeyError) {
    return { error: deviceKeyError };
  }

  const kdfOutputBytes = await input.deriveVaultKdfOutput(
    input.masterPassword,
    deviceKey,
    deviceKeyAvailable,
  );
  let activeKey: CryptoKey;
  let shouldBackfillVerifier = !input.verificationHash;
  let vaultEncryptionKey: Uint8Array | undefined;
  let userKeyBytes: Uint8Array | null = null;

  try {
    if (input.encryptedUserKey) {
      const unwrapped = await unwrapAndVerifyUserKey(input, kdfOutputBytes, deviceKeyAvailable);
      activeKey = unwrapped.userKey;
      userKeyBytes = unwrapped.userKeyBytes;
      const upgraded = await upgradeUserKeyWrapperIfNeeded(input, kdfOutputBytes, deviceKey, deviceKeyAvailable);
      if (upgraded) {
        shouldBackfillVerifier = false;
      }
      vaultEncryptionKey = new Uint8Array(userKeyBytes);
    } else {
      const legacyKey = await importMasterKey(kdfOutputBytes);
      const isValid = input.verificationHash
        ? await verifyKey(input.verificationHash, legacyKey)
        : await recoverLegacyUserKeyWithoutVerifier({ userId: input.userId, candidateKey: legacyKey });
      if (!isValid) {
        recordFailedAttempt();
        return {
          error: requiresDeviceKey(input.vaultProtectionMode) && deviceKeyAvailable
            ? createDeviceKeyInvalidError()
            : createMasterPasswordInvalidError(),
        };
      }

      resetUnlockAttempts();
      const migration = await migrateLegacyVaultToUserKey({
        userId: input.userId,
        salt: input.salt,
        kdfVersion: input.kdfVersion,
        vaultProtectionMode: input.vaultProtectionMode,
        kdfOutputBytes,
      });
      await input.applyCredentialUpdates({
        verificationHash: migration.verifier,
        encryptedUserKey: migration.encryptedUserKey,
      });
      activeKey = migration.userKey;
      shouldBackfillVerifier = false;
      vaultEncryptionKey = new Uint8Array(kdfOutputBytes);
    }
  } finally {
    userKeyBytes?.fill(0);
    kdfOutputBytes.fill(0);
  }

  await repairBrokenKdfUpgradeIfNeeded({
    userId: input.userId,
    masterPassword: input.masterPassword,
    salt: input.salt,
    kdfVersion: input.kdfVersion,
    activeKey,
  });

  if (!isTauriDevUserId(input.userId)) {
    try {
      await migrateLegacyPrivateKeys({
        userId: input.userId,
        masterPassword: input.masterPassword,
        activeKey,
      });
    } catch (error) {
      console.warn('Private key USK migration failed, will retry next unlock:', error);
    }
  }

  const twoFactorResult = await input.enforceVaultTwoFactorBeforeKeyRelease(input.options);
  if (twoFactorResult.error) {
    return twoFactorResult;
  }

  const finalizeResult = await input.finalizeVaultUnlock(activeKey, vaultEncryptionKey);
  if (finalizeResult.error) {
    return finalizeResult;
  }

  if (shouldBackfillVerifier && !isTauriDevUserId(input.userId)) {
    await backfillVerifier(input, activeKey);
  }

  return { error: null, vaultEncryptionKey };
}

async function unwrapAndVerifyUserKey(
  input: VaultMasterUnlockInput,
  kdfOutputBytes: Uint8Array,
  deviceKeyAvailable: boolean,
): Promise<{ userKey: CryptoKey; userKeyBytes: Uint8Array }> {
  let userKeyBytes: Uint8Array;
  try {
    userKeyBytes = await unwrapUserKeyBytes(input.encryptedUserKey!, kdfOutputBytes);
  } catch (error) {
    if (requiresDeviceKey(input.vaultProtectionMode) && deviceKeyAvailable) {
      throw createDeviceKeyInvalidError();
    }
    throw error;
  }

  try {
    const userKey = await importMasterKey(userKeyBytes);

    if (input.verificationHash) {
      const isValid = await verifyKey(input.verificationHash, userKey);
      if (!isValid) {
        throw requiresDeviceKey(input.vaultProtectionMode) && deviceKeyAvailable
          ? createDeviceKeyInvalidError()
          : createMasterPasswordInvalidError();
      }
    }

    resetUnlockAttempts();
    return { userKey, userKeyBytes };
  } catch (error) {
    userKeyBytes.fill(0);
    throw error;
  }
}

async function upgradeUserKeyWrapperIfNeeded(
  input: VaultMasterUnlockInput,
  kdfOutputBytes: Uint8Array,
  deviceKey: Uint8Array | null,
  deviceKeyAvailable: boolean,
): Promise<boolean> {
  try {
    const upgrade = isNativeDeviceKeyBridgeRuntime() && deviceKeyAvailable
      ? { upgraded: false, activeVersion: input.kdfVersion, newEncryptedUserKey: null, newVerifier: null }
      : await attemptKdfUpgrade(
        input.masterPassword,
        input.salt,
        input.kdfVersion,
        deviceKey || undefined,
        input.encryptedUserKey!,
        kdfOutputBytes,
      );
    if (upgrade.upgraded && upgrade.newEncryptedUserKey && upgrade.newVerifier) {
      const { error } = await supabase
        .from('profiles')
        .update({
          master_password_verifier: upgrade.newVerifier,
          kdf_version: upgrade.activeVersion,
          encrypted_user_key: upgrade.newEncryptedUserKey,
        } as Record<string, unknown>)
        .eq('user_id', input.userId);
      if (!error) {
        await input.applyCredentialUpdates({
          verificationHash: upgrade.newVerifier,
          kdfVersion: upgrade.activeVersion,
          encryptedUserKey: upgrade.newEncryptedUserKey,
        });
        await saveOfflineCredentials(
          input.userId,
          input.salt,
          upgrade.newVerifier,
          upgrade.activeVersion,
          upgrade.newEncryptedUserKey,
          input.vaultProtectionMode,
        );
        console.info(`KDF upgraded (USK rewrap-only) from v${input.kdfVersion} to v${upgrade.activeVersion}. No vault re-encryption needed.`);
        return true;
      }
    }
  } catch {
    console.warn('KDF upgrade (USK path) failed, continuing with current version');
  }

  return false;
}

async function backfillVerifier(
  input: VaultMasterUnlockInput,
  activeKey: CryptoKey,
): Promise<void> {
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
