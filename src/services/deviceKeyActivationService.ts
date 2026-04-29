import {
  createVerificationHash,
  deriveKey,
  deriveRawKey,
  importMasterKey,
  reEncryptVault,
  rewrapUserKey,
  unwrapUserKey,
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

export interface DeviceKeyActivationInput {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  encryptionKey: CryptoKey;
  encryptedUserKey: string | null;
  currentDeviceKey: Uint8Array | null;
}

export interface DeviceKeyActivationState {
  encryptionKey?: CryptoKey;
  encryptedUserKey: string | null;
  verificationHash: string;
  currentDeviceKey: Uint8Array | null;
  deviceKeyActive: boolean;
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

  try {
    if (await checkHasDeviceKey(userId)) {
      return { error: new Error('A Device Key already exists in the OS keychain for this user.') };
    }

    await generateAndStoreNativeDeviceKey(userId);
    nativeDeviceKeyStored = true;

    const deriveNativeKdfOutput = async (): Promise<Uint8Array> => {
      const argon2Output = await deriveRawKey(masterPassword, salt, kdfVersion);
      try {
        return await deriveNativeDeviceProtectedKey(userId, argon2Output);
      } finally {
        argon2Output.fill(0);
      }
    };

    const oldKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion);
    const newKdfOutputBytes = await deriveNativeKdfOutput();
    let newEncryptedUserKey: string;
    try {
      newEncryptedUserKey = await rewrapUserKey(
        encryptedUserKey!,
        oldKdfOutputBytes,
        newKdfOutputBytes,
      );
    } finally {
      oldKdfOutputBytes.fill(0);
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
      newVerifier,
      newEncryptedUserKey,
    });
    await saveOfflineCredentials(
      userId,
      salt,
      newVerifier,
      kdfVersion,
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
        vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      },
    };
  } catch (error) {
    if (nativeDeviceKeyStored) {
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

  if (encryptedUserKey) {
    const oldKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, currentDeviceKey || undefined);
    const newKdfOutputBytes = await deriveRawKey(masterPassword, salt, kdfVersion, newDeviceKey);
    let newEncryptedUserKey: string;
    try {
      newEncryptedUserKey = await rewrapUserKey(
        encryptedUserKey,
        oldKdfOutputBytes,
        newKdfOutputBytes,
      );
    } finally {
      oldKdfOutputBytes.fill(0);
      newKdfOutputBytes.fill(0);
    }

    const verifierKdfOutput = await deriveRawKey(masterPassword, salt, kdfVersion, newDeviceKey);
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

    await saveOfflineCredentials(
      userId,
      salt,
      newVerifier,
      kdfVersion,
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
        vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      },
    };
  }

  const newKey = await deriveKey(masterPassword, salt, kdfVersion, newDeviceKey);
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
    newVerifier,
    newEncryptedUserKey: null,
  });
  await saveOfflineCredentials(
    userId,
    salt,
    newVerifier,
    kdfVersion,
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
      vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
    },
  };
}

async function persistDeviceKeyProfileState(input: {
  userId: string;
  newVerifier: string;
  newEncryptedUserKey: string | null;
}): Promise<void> {
  const { userId, newVerifier, newEncryptedUserKey } = input;
  const enabledAt = new Date().toISOString();
  const updatePayload: Record<string, unknown> = {
    master_password_verifier: newVerifier,
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
