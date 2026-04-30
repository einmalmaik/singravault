import {
  createVerificationHash,
  CURRENT_KDF_VERSION,
  deriveRawKey,
  KDF_PARAMS,
  rewrapUserKey,
  unwrapUserKey,
} from '@/services/cryptoService';
import {
  deleteDeviceKey,
  getDeviceKey,
  hasDeviceKey,
} from '@/services/deviceKeyService';
import {
  deriveNativeDeviceProtectedKey,
  isNativeDeviceKeyBridgeRuntime,
} from '@/services/deviceKeyNativeBridge';
import {
  createDeviceKeyMissingError,
  createUserKeyMigrationRequiredError,
  VAULT_PROTECTION_MODE_MASTER_ONLY,
  type VaultProtectionMode,
} from '@/services/deviceKeyProtectionPolicy';
import { saveOfflineCredentials } from '@/services/offlineVaultService';
import { getTwoFactorRequirement } from '@/services/twoFactorService';
import { supabase } from '@/integrations/supabase/client';

export class DeviceKeyDeactivationError extends Error {
  constructor(
    public readonly code:
      | 'LOCAL_DEVICE_KEY_REQUIRED'
      | 'TWO_FACTOR_REQUIRED'
      | 'TWO_FACTOR_FAILED'
      | 'SECURITY_WORD_FAILED'
      | 'USER_KEY_REWRAP_FAILED'
      | 'PROFILE_PERSIST_FAILED',
    message: string,
  ) {
    super(message);
    this.name = 'DeviceKeyDeactivationError';
  }
}

export interface DeviceKeyDeactivationInput {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  encryptedUserKey: string | null;
  currentDeviceKey: Uint8Array | null;
  twoFactorCode?: string | null;
  confirmationWord: string;
}

export interface DeviceKeyDeactivationState {
  encryptedUserKey: string;
  verificationHash: string;
  currentDeviceKey: null;
  deviceKeyActive: boolean;
  kdfVersion: number;
  vaultProtectionMode: VaultProtectionMode;
}

export interface DeviceKeyDeactivationResult {
  error: Error | null;
  state?: DeviceKeyDeactivationState;
}

export async function deactivateDeviceKeyProtection(
  input: DeviceKeyDeactivationInput,
): Promise<DeviceKeyDeactivationResult> {
  try {
    if (!input.encryptedUserKey) {
      return { error: createUserKeyMigrationRequiredError() };
    }

    await requireLocalDeviceKey(input);
    await requireVaultTwoFactorInputIfNeeded(input.userId, input.twoFactorCode);

    const targetKdfVersion = Math.max(input.kdfVersion, CURRENT_KDF_VERSION);
    const newKdfOutputBytes = await deriveRawKey(input.masterPassword, input.salt, targetKdfVersion);
    let newEncryptedUserKey: string;
    try {
      newEncryptedUserKey = await rewrapUserKeyForDeviceKeyDeactivation({
        ...input,
        encryptedUserKey: input.encryptedUserKey,
        newKdfOutputBytes,
      });
    } finally {
      newKdfOutputBytes.fill(0);
    }

    const verifierKdfOutputBytes = await deriveRawKey(input.masterPassword, input.salt, targetKdfVersion);
    let newVerifier: string;
    try {
      const newUserKey = await unwrapUserKey(newEncryptedUserKey, verifierKdfOutputBytes);
      newVerifier = await createVerificationHash(newUserKey);
    } finally {
      verifierKdfOutputBytes.fill(0);
    }

    await persistMasterOnlyProfileState({
      userId: input.userId,
      kdfVersion: targetKdfVersion,
      newVerifier,
      newEncryptedUserKey,
      confirmationWord: input.confirmationWord,
      twoFactorCode: input.twoFactorCode,
    });
    await saveOfflineCredentials(
      input.userId,
      input.salt,
      newVerifier,
      targetKdfVersion,
      newEncryptedUserKey,
      VAULT_PROTECTION_MODE_MASTER_ONLY,
    );

    await deleteDeviceKey(input.userId);

    return {
      error: null,
      state: {
        encryptedUserKey: newEncryptedUserKey,
        verificationHash: newVerifier,
        currentDeviceKey: null,
        deviceKeyActive: false,
        kdfVersion: targetKdfVersion,
        vaultProtectionMode: VAULT_PROTECTION_MODE_MASTER_ONLY,
      },
    };
  } catch (error) {
    return {
      error: error instanceof Error ? error : new Error('Failed to disable Device Key protection.'),
    };
  }
}

async function requireLocalDeviceKey(input: DeviceKeyDeactivationInput): Promise<void> {
  if (!(await hasDeviceKey(input.userId))) {
    throw createDeviceKeyMissingError();
  }

  if (!isNativeDeviceKeyBridgeRuntime()) {
    const deviceKey = input.currentDeviceKey ?? await getDeviceKey(input.userId);
    if (!deviceKey) {
      throw new DeviceKeyDeactivationError(
        'LOCAL_DEVICE_KEY_REQUIRED',
        'Device Key protection can only be disabled from a device that already has the local Device Key.',
      );
    }
  }
}

async function requireVaultTwoFactorInputIfNeeded(userId: string, twoFactorCode: string | null | undefined): Promise<void> {
  const requirement = await getTwoFactorRequirement({
    userId,
    context: 'vault_unlock',
  });

  if (requirement.status === 'unavailable') {
    throw new DeviceKeyDeactivationError(
      'TWO_FACTOR_REQUIRED',
      'Vault 2FA status is unavailable. Device Key protection was not changed.',
    );
  }

  if (!requirement.required) {
    return;
  }

  if (!twoFactorCode?.trim()) {
    throw new DeviceKeyDeactivationError(
      'TWO_FACTOR_REQUIRED',
      'Current authenticator code is required to disable Device Key protection.',
    );
  }

  // The actual TOTP check is performed by auth-2fa during profile persistence.
}

async function rewrapUserKeyForDeviceKeyDeactivation(input: {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  encryptedUserKey: string;
  currentDeviceKey: Uint8Array | null;
  newKdfOutputBytes: Uint8Array;
}): Promise<string> {
  const candidateVersions = getDeviceKeyDeactivationKdfCandidates(input.kdfVersion);

  for (const candidateVersion of candidateVersions) {
    const oldKdfOutputBytes = await deriveCurrentDeviceProtectedKdfOutput({
      userId: input.userId,
      masterPassword: input.masterPassword,
      salt: input.salt,
      kdfVersion: candidateVersion,
      currentDeviceKey: input.currentDeviceKey,
    });
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
    } finally {
      oldKdfOutputBytes.fill(0);
    }
  }

  throw new DeviceKeyDeactivationError(
    'USER_KEY_REWRAP_FAILED',
    'Could not unwrap the current vault UserKey with the supplied master password and local Device Key.',
  );
}

async function deriveCurrentDeviceProtectedKdfOutput(input: {
  userId: string;
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  currentDeviceKey: Uint8Array | null;
}): Promise<Uint8Array> {
  if (!isNativeDeviceKeyBridgeRuntime()) {
    const deviceKey = input.currentDeviceKey ?? await getDeviceKey(input.userId);
    if (!deviceKey) {
      throw createDeviceKeyMissingError();
    }

    return deriveRawKey(input.masterPassword, input.salt, input.kdfVersion, deviceKey);
  }

  const argon2Output = await deriveRawKey(input.masterPassword, input.salt, input.kdfVersion);
  try {
    return await deriveNativeDeviceProtectedKey(input.userId, argon2Output);
  } finally {
    argon2Output.fill(0);
  }
}

function getDeviceKeyDeactivationKdfCandidates(profileKdfVersion: number): number[] {
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

async function persistMasterOnlyProfileState(input: {
  userId: string;
  kdfVersion: number;
  newVerifier: string;
  newEncryptedUserKey: string;
  confirmationWord: string;
  twoFactorCode?: string | null;
}): Promise<void> {
  const { data, error } = await supabase.functions.invoke<{ success?: boolean; error?: string; errorCode?: string }>('auth-2fa', {
    body: {
      action: 'complete-device-key-deactivation',
      confirmationWord: input.confirmationWord,
      twoFactorCode: input.twoFactorCode ?? null,
      encryptedUserKey: input.newEncryptedUserKey,
      verificationHash: input.newVerifier,
      kdfVersion: input.kdfVersion,
      targetProtectionMode: VAULT_PROTECTION_MODE_MASTER_ONLY,
    },
  });

  if (error || !data?.success) {
    throw new DeviceKeyDeactivationError(
      data?.errorCode === 'INVALID_CONFIRMATION' ? 'SECURITY_WORD_FAILED' : 'PROFILE_PERSIST_FAILED',
      data?.error || error?.message || 'Failed to update Device Key protection state.',
    );
  }
}
