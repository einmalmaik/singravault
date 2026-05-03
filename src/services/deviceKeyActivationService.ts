import {
  createVerificationHash,
  CURRENT_KDF_VERSION,
  deriveKey,
  deriveRawKey,
  importMasterKey,
  KDF_PARAMS,
  migrateToUserKey,
  reEncryptVault,
  rewrapUserKey,
  unwrapUserKey,
  verifyKey,
} from '@/services/cryptoService';
import {
  deleteDeviceKey,
  generateDeviceKey,
  hasDeviceKey as checkHasDeviceKey,
  storeDeviceKey,
} from '@/services/deviceKeyService';
import {
  deriveNativeDeviceProtectedKey,
  generateAndStoreNativeDeviceKey,
  isNativeDeviceKeyBridgeRuntime,
} from '@/services/deviceKeyNativeBridge';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  createUserKeyMigrationRequiredError,
  type VaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import { saveOfflineCredentials } from '@/services/offlineVaultService';
import { isLocalSecretStoreSupported } from '@/platform/localSecretStore';
import { supabase } from '@/integrations/supabase/client';

class DeviceKeyActivationRewrapError extends Error {
  constructor() {
    super('Could not unwrap the current vault UserKey with the supplied master password and known KDF parameters.');
    this.name = 'DeviceKeyActivationRewrapError';
  }
}

export interface DeviceKeyActivationInput {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  encryptionKey: CryptoKey;
  encryptedUserKey: string | null;
  verificationHash: string | null;
  currentDeviceKey: Uint8Array | null;
}

export interface DeviceKeyActivationState {
  encryptionKey?: CryptoKey;
  encryptedUserKey: string | null;
  verificationHash: string;
  currentDeviceKey: Uint8Array | null;
  deviceKeyActive: boolean;
  kdfVersion: number;
  vaultProtectionMode: VaultProtectionMode;
}

export interface DeviceKeyActivationResult {
  error: Error | null;
  state?: DeviceKeyActivationState;
}

export async function activateDeviceKeyProtection(
  input: DeviceKeyActivationInput,
): Promise<DeviceKeyActivationResult> {
  try {
    if (!(await isLocalSecretStoreSupported())) {
      return { error: new Error('Secure local secret storage is not available in this runtime.') };
    }

    if (!input.encryptedUserKey) {
      return { error: createUserKeyMigrationRequiredError() };
    }

    if (isNativeDeviceKeyBridgeRuntime()) {
      return await activateNativeDeviceKeyProtection(input);
    }

    return await activateBrowserDeviceKeyProtection(input);
  } catch (error) {
    console.error('Failed to enable Device Key:', error);
    return {
      error: error instanceof Error ? error : new Error('Failed to enable Device Key.'),
    };
  }
}

async function activateNativeDeviceKeyProtection(
  input: DeviceKeyActivationInput,
): Promise<DeviceKeyActivationResult> {
  const { userId, masterPassword, salt, kdfVersion, encryptionKey, encryptedUserKey } = input;
  let nativeDeviceKeyStored = false;
  let profileStatePersisted = false;
  const targetKdfVersion = Math.max(kdfVersion, CURRENT_KDF_VERSION);

  try {
    if (await checkHasDeviceKey(userId)) {
      return { error: new Error('A Device Key already exists in the OS keychain for this user.') };
    }

    await generateAndStoreNativeDeviceKey(userId);
    nativeDeviceKeyStored = true;

    const deriveNativeKdfOutput = async (): Promise<Uint8Array> => {
      const argon2Output = await deriveRawKey(masterPassword, salt, targetKdfVersion);
      try {
        return await deriveNativeDeviceProtectedKey(userId, argon2Output);
      } finally {
        argon2Output.fill(0);
      }
    };

    const newKdfOutputBytes = await deriveNativeKdfOutput();
    let newEncryptedUserKey: string;
    try {
      newEncryptedUserKey = await rewrapUserKeyForDeviceActivation({
        encryptedUserKey: encryptedUserKey!,
        masterPassword,
        salt,
        kdfVersion,
        newKdfOutputBytes,
        verificationHash: input.verificationHash,
      });
    } finally {
      newKdfOutputBytes.fill(0);
    }

    const verifierKdfOutput = await deriveNativeKdfOutput();
    let newVerifier: string;
    try {
      const newUserKey = await unwrapUserKey(newEncryptedUserKey, verifierKdfOutput);
      newVerifier = await createVerificationHash(newUserKey);
    } finally {
      verifierKdfOutput.fill(0);
    }

    await persistDeviceKeyProfileState({
      userId,
      kdfVersion: targetKdfVersion,
      newVerifier,
      newEncryptedUserKey,
    });
    profileStatePersisted = true;
    await saveOfflineCredentialsAfterDeviceKeyCommit(
      userId,
      salt,
      newVerifier,
      targetKdfVersion,
      newEncryptedUserKey,
      VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
    );

    console.info('Device Key enabled (native USK path). No vault re-encryption needed.');
    return {
      error: null,
      state: {
        encryptionKey,
        encryptedUserKey: newEncryptedUserKey,
        verificationHash: newVerifier,
        currentDeviceKey: null,
        deviceKeyActive: true,
        kdfVersion: targetKdfVersion,
        vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      },
    };
  } catch (error) {
    if (nativeDeviceKeyStored && !profileStatePersisted) {
      try {
        await deleteDeviceKey(userId);
      } catch {
        // Best-effort rollback only; never log local secret material.
      }
    }
    throw error;
  }
}

async function activateBrowserDeviceKeyProtection(
  input: DeviceKeyActivationInput,
): Promise<DeviceKeyActivationResult> {
  const {
    userId,
    masterPassword,
    salt,
    kdfVersion,
    encryptionKey,
    encryptedUserKey,
    currentDeviceKey,
  } = input;
  const newDeviceKey = generateDeviceKey();
  const targetKdfVersion = Math.max(kdfVersion, CURRENT_KDF_VERSION);

  if (encryptedUserKey) {
    const newKdfOutputBytes = await deriveRawKey(masterPassword, salt, targetKdfVersion, newDeviceKey);
    let newEncryptedUserKey: string;
    try {
      newEncryptedUserKey = await rewrapUserKeyForDeviceActivation({
        encryptedUserKey,
        masterPassword,
        salt,
        kdfVersion,
        newKdfOutputBytes,
        verificationHash: input.verificationHash,
        currentDeviceKey,
      });
    } finally {
      newKdfOutputBytes.fill(0);
    }

    const verifierKdfOutput = await deriveRawKey(masterPassword, salt, targetKdfVersion, newDeviceKey);
    let newVerifier: string;
    try {
      const newUserKey = await unwrapUserKey(newEncryptedUserKey, verifierKdfOutput);
      newVerifier = await createVerificationHash(newUserKey);
    } finally {
      verifierKdfOutput.fill(0);
    }

    await storeDeviceKey(userId, newDeviceKey);
    try {
      await persistDeviceKeyProfileState({
        userId,
        kdfVersion: targetKdfVersion,
        newVerifier,
        newEncryptedUserKey,
      });
    } catch (error) {
      try {
        await deleteDeviceKey(userId);
      } catch {
        // Best-effort rollback only; never log local secret material.
      }
      throw error;
    }

    await saveOfflineCredentialsAfterDeviceKeyCommit(
      userId,
      salt,
      newVerifier,
      targetKdfVersion,
      newEncryptedUserKey,
      VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
    );

    console.info('Device Key enabled (USK path). No vault re-encryption needed.');
    return {
      error: null,
      state: {
        encryptionKey,
        encryptedUserKey: newEncryptedUserKey,
        verificationHash: newVerifier,
        currentDeviceKey: newDeviceKey,
        deviceKeyActive: true,
        kdfVersion: targetKdfVersion,
        vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      },
    };
  }

  const newKey = await deriveKey(masterPassword, salt, targetKdfVersion, newDeviceKey);
  const newVerifier = await createVerificationHash(newKey);
  const { data: vaultItems } = await supabase
    .from('vault_items')
    .select('id, encrypted_data')
    .eq('user_id', userId);
  const { data: categories } = await supabase
    .from('categories')
    .select('id, name, icon, color')
    .eq('user_id', userId);

  const reEncResult = await reEncryptVault(vaultItems || [], categories || [], encryptionKey, newKey);
  await persistReencryptedVaultRows(userId, reEncResult);
  await storeDeviceKey(userId, newDeviceKey);
  await persistDeviceKeyProfileState({
    userId,
    kdfVersion: targetKdfVersion,
    newVerifier,
    newEncryptedUserKey: null,
  });
  await saveOfflineCredentialsAfterDeviceKeyCommit(
    userId,
    salt,
    newVerifier,
    targetKdfVersion,
    null,
    VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  );

  console.info(
    `Device Key enabled. Re-encrypted ${reEncResult.itemsReEncrypted} items, `
    + `${reEncResult.categoriesReEncrypted} categories.`,
  );
  return {
    error: null,
    state: {
      encryptionKey: newKey,
      encryptedUserKey: null,
      verificationHash: newVerifier,
      currentDeviceKey: newDeviceKey,
      deviceKeyActive: true,
      kdfVersion: targetKdfVersion,
      vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
    },
  };
}

async function rewrapUserKeyForDeviceActivation(input: {
  encryptedUserKey: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  newKdfOutputBytes: Uint8Array;
  verificationHash: string | null;
  currentDeviceKey?: Uint8Array | null;
}): Promise<string> {
  const candidateVersions = getDeviceActivationKdfCandidates(input.kdfVersion);
  let lastUnwrapFailure: unknown = null;

  for (const candidateVersion of candidateVersions) {
    const oldKdfOutputBytes = await deriveRawKey(
      input.masterPassword,
      input.salt,
      candidateVersion,
      input.currentDeviceKey || undefined,
    );
    try {
      return await rewrapUserKey(
        input.encryptedUserKey,
        oldKdfOutputBytes,
        input.newKdfOutputBytes,
      );
    } catch (error) {
      if (!isUserKeyUnwrapFailure(error)) {
        throw error;
      }
      lastUnwrapFailure = error;
      // Try the next known KDF parameter set. This covers stale profile
      // metadata without ever accepting master-password-only unlock for a
      // Device-Key-protected vault.
    } finally {
      oldKdfOutputBytes.fill(0);
    }
  }

  if (input.verificationHash) {
    const recovered = await rewrapDeterministicMigratedUserKeyForActivation({
      masterPassword: input.masterPassword,
      salt: input.salt,
      candidateVersions,
      verificationHash: input.verificationHash,
      newKdfOutputBytes: input.newKdfOutputBytes,
      currentDeviceKey: input.currentDeviceKey,
    });
    if (recovered) {
      return recovered;
    }
  }

  if (lastUnwrapFailure && isUserKeyUnwrapFailure(lastUnwrapFailure)) {
    throw new DeviceKeyActivationRewrapError();
  }
  throw new DeviceKeyActivationRewrapError();
}

async function rewrapDeterministicMigratedUserKeyForActivation(input: {
  masterPassword: string;
  salt: string;
  candidateVersions: number[];
  verificationHash: string;
  newKdfOutputBytes: Uint8Array;
  currentDeviceKey?: Uint8Array | null;
}): Promise<string | null> {
  for (const candidateVersion of input.candidateVersions) {
    const oldKdfOutputBytes = await deriveRawKey(
      input.masterPassword,
      input.salt,
      candidateVersion,
      input.currentDeviceKey || undefined,
    );
    try {
      const migrated = await migrateToUserKey(oldKdfOutputBytes);
      if (!(await verifyKey(input.verificationHash, migrated.userKey))) {
        continue;
      }

      return await rewrapUserKey(
        migrated.encryptedUserKey,
        oldKdfOutputBytes,
        input.newKdfOutputBytes,
      );
    } catch (error) {
      if (!isUserKeyUnwrapFailure(error)) {
        throw error;
      }
    } finally {
      oldKdfOutputBytes.fill(0);
    }
  }

  return null;
}

function getDeviceActivationKdfCandidates(profileKdfVersion: number): number[] {
  const knownVersions = Object.keys(KDF_PARAMS)
    .map(Number)
    .filter((version) => Number.isFinite(version))
    .sort((a, b) => b - a);
  const preferred = [profileKdfVersion, CURRENT_KDF_VERSION]
    .filter((version) => KDF_PARAMS[version]);

  return [...new Set([...preferred, ...knownVersions])];
}

function isUserKeyUnwrapFailure(error: unknown): boolean {
  return error instanceof DOMException
    && (error.name === 'OperationError' || error.name === 'DataError');
}

async function persistDeviceKeyProfileState(input: {
  userId: string;
  kdfVersion: number;
  newVerifier: string;
  newEncryptedUserKey: string | null;
}): Promise<void> {
  const { userId, kdfVersion, newVerifier, newEncryptedUserKey } = input;
  const enabledAt = new Date().toISOString();
  const updatePayload: Record<string, unknown> = {
    master_password_verifier: newVerifier,
    kdf_version: kdfVersion,
    vault_protection_mode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
    device_key_version: 1,
    device_key_enabled_at: enabledAt,
    device_key_backup_acknowledged_at: null,
  };

  if (newEncryptedUserKey !== null) {
    updatePayload.encrypted_user_key = newEncryptedUserKey;
  }

  const { error } = await supabase
    .from('profiles')
    .update(updatePayload)
    .eq('user_id', userId);

  if (error) {
    throw new Error(`Failed to update profile: ${error.message}`);
  }
}

async function saveOfflineCredentialsAfterDeviceKeyCommit(
  userId: string,
  salt: string,
  verificationHash: string,
  kdfVersion: number,
  encryptedUserKey: string | null,
  vaultProtectionMode: VaultProtectionMode,
): Promise<void> {
  try {
    await saveOfflineCredentials(
      userId,
      salt,
      verificationHash,
      kdfVersion,
      encryptedUserKey,
      vaultProtectionMode,
    );
  } catch {
    console.warn(
      'Device Key profile state was updated, but offline credential cache persistence failed. '
      + 'Offline unlock will retry after the next successful credential refresh.',
    );
  }
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
      .update({
        name: categoryUpdate.name,
        icon: categoryUpdate.icon,
        color: categoryUpdate.color,
      })
      .eq('id', categoryUpdate.id)
      .eq('user_id', userId);
    if (error) {
      throw new Error(`Failed to update category ${categoryUpdate.id}: ${error.message}`);
    }
  }
}
