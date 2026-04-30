import {
  attemptKdfUpgrade,
  importMasterKey,
  reEncryptVault,
  unwrapUserKey,
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
  finalizeVaultUnlock: (activeKey: CryptoKey) => Promise<{ error: Error | null }>;
  openDuressVault: (activeKey: CryptoKey) => void;
  applyCredentialUpdates: (updates: {
    verificationHash?: string;
    kdfVersion?: number;
    encryptedUserKey?: string | null;
  }) => Promise<void> | void;
}

export async function unlockVaultWithMasterPassword(
  input: VaultMasterUnlockInput,
): Promise<{ error: Error | null }> {
  const cooldown = getUnlockCooldown();
  if (cooldown !== null) {
    const seconds = Math.ceil(cooldown / 1000);
    return { error: new Error(`Too many attempts. Try again in ${seconds}s.`) };
  }

  try {
    const duressResult = await tryDuressUnlock(input);
    if (duressResult.handled) {
      return { error: duressResult.error };
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
  if (!input.duressConfig?.enabled || !getServiceHooks().attemptDualUnlock) {
    return { handled: false, error: null };
  }

  if (!input.verificationHash) {
    return {
      handled: true,
      error: new Error('Duress unlock requires a current verifier. Please unlock online once with your master password.'),
    };
  }

  const result = await getServiceHooks().attemptDualUnlock!(
    input.masterPassword,
    input.salt,
    input.verificationHash,
    input.kdfVersion,
    input.duressConfig,
  );

  if (result.mode === 'invalid') {
    recordFailedAttempt();
    return { handled: true, error: new Error('Invalid master password') };
  }

  resetUnlockAttempts();
  if (result.mode === 'duress') {
    const twoFactorResult = await input.enforceVaultTwoFactorBeforeKeyRelease(input.options);
    if (twoFactorResult.error) {
      return { handled: true, error: twoFactorResult.error };
    }
    input.openDuressVault(result.key!);
    return { handled: true, error: null };
  }

  let activeKey = result.key!;
  let shouldBackfillVerifier = !input.verificationHash;
  const upgraded = await upgradeLegacyDirectKdfIfNeeded(input, activeKey);
  if (upgraded.activeKey) {
    activeKey = upgraded.activeKey;
    shouldBackfillVerifier = false;
  }

  await repairBrokenKdfUpgradeIfNeeded({
    userId: input.userId,
    masterPassword: input.masterPassword,
    salt: input.salt,
    kdfVersion: input.kdfVersion,
    activeKey,
    contextLabel: 'duress path',
  });

  const twoFactorResult = await input.enforceVaultTwoFactorBeforeKeyRelease(input.options);
  if (twoFactorResult.error) {
    return { handled: true, error: twoFactorResult.error };
  }

  const finalizeResult = await input.finalizeVaultUnlock(activeKey);
  if (finalizeResult.error) {
    return { handled: true, error: finalizeResult.error };
  }

  if (shouldBackfillVerifier) {
    await backfillVerifier(input, activeKey);
  }

  return { handled: true, error: null };
}

async function unlockWithPrimaryVaultKey(
  input: VaultMasterUnlockInput,
): Promise<{ error: Error | null }> {
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

  try {
    if (input.encryptedUserKey) {
      activeKey = await unwrapAndVerifyUserKey(input, kdfOutputBytes, deviceKeyAvailable);
      const upgraded = await upgradeUserKeyWrapperIfNeeded(input, kdfOutputBytes, deviceKey, deviceKeyAvailable);
      if (upgraded) {
        shouldBackfillVerifier = false;
      }
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
    }
  } finally {
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

  const finalizeResult = await input.finalizeVaultUnlock(activeKey);
  if (finalizeResult.error) {
    return finalizeResult;
  }

  if (shouldBackfillVerifier && !isTauriDevUserId(input.userId)) {
    await backfillVerifier(input, activeKey);
  }

  return { error: null };
}

async function unwrapAndVerifyUserKey(
  input: VaultMasterUnlockInput,
  kdfOutputBytes: Uint8Array,
  deviceKeyAvailable: boolean,
): Promise<CryptoKey> {
  let userKey: CryptoKey;
  try {
    userKey = await unwrapUserKey(input.encryptedUserKey!, kdfOutputBytes);
  } catch (error) {
    if (requiresDeviceKey(input.vaultProtectionMode) && deviceKeyAvailable) {
      throw createDeviceKeyInvalidError();
    }
    throw error;
  }

  if (input.verificationHash) {
    const isValid = await verifyKey(input.verificationHash, userKey);
    if (!isValid) {
      throw requiresDeviceKey(input.vaultProtectionMode) && deviceKeyAvailable
        ? createDeviceKeyInvalidError()
        : createMasterPasswordInvalidError();
    }
  }

  resetUnlockAttempts();
  return userKey;
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

async function upgradeLegacyDirectKdfIfNeeded(
  input: VaultMasterUnlockInput,
  currentKey: CryptoKey,
): Promise<{ activeKey: CryptoKey | null }> {
  try {
    const upgrade = await attemptKdfUpgrade(input.masterPassword, input.salt, input.kdfVersion);
    if (!upgrade.upgraded || !upgrade.newKey || !upgrade.newVerifier) {
      return { activeKey: null };
    }

    const { data: vaultItems } = await supabase
      .from('vault_items')
      .select('id, encrypted_data')
      .eq('user_id', input.userId);
    const { data: categories } = await supabase
      .from('categories')
      .select('id, name, icon, color')
      .eq('user_id', input.userId);
    const reEncResult = await reEncryptVault(vaultItems || [], categories || [], currentKey, upgrade.newKey);
    await persistReencryptedVaultRows(input.userId, reEncResult);

    const { error } = await supabase
      .from('profiles')
      .update({
        master_password_verifier: upgrade.newVerifier,
        kdf_version: upgrade.activeVersion,
      } as Record<string, unknown>)
      .eq('user_id', input.userId);
    if (!error) {
      await input.applyCredentialUpdates({
        verificationHash: upgrade.newVerifier,
        kdfVersion: upgrade.activeVersion,
      });
      await saveOfflineCredentials(
        input.userId,
        input.salt,
        upgrade.newVerifier,
        upgrade.activeVersion,
        input.encryptedUserKey,
        input.vaultProtectionMode,
      );
      console.info(
        `KDF upgraded from v${input.kdfVersion} to v${upgrade.activeVersion}. `
        + `Re-encrypted ${reEncResult.itemsReEncrypted} items and `
        + `${reEncResult.categoriesReEncrypted} categories.`,
      );
      return { activeKey: upgrade.newKey };
    }
  } catch (error) {
    console.warn('KDF upgrade: re-encryption failed, staying on old version', error);
  }

  return { activeKey: null };
}

async function persistReencryptedVaultRows(
  userId: string,
  reEncResult: Awaited<ReturnType<typeof reEncryptVault>>,
): Promise<void> {
  for (const itemUpdate of reEncResult.itemUpdates) {
    const { error } = await supabase
      .from('vault_items')
      .update({ encrypted_data: itemUpdate.encrypted_data })
      .eq('id', itemUpdate.id)
      .eq('user_id', userId);
    if (error) {
      throw new Error(`Failed to update item ${itemUpdate.id}: ${error.message}`);
    }
  }

  for (const categoryUpdate of reEncResult.categoryUpdates) {
    const { error } = await supabase
      .from('categories')
      .update({ name: categoryUpdate.name, icon: categoryUpdate.icon, color: categoryUpdate.color })
      .eq('id', categoryUpdate.id)
      .eq('user_id', userId);
    if (error) {
      throw new Error(`Failed to update category ${categoryUpdate.id}: ${error.message}`);
    }
  }
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
