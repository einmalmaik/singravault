import { deriveRawKey } from './cryptoService';
import {
  deriveNativeDeviceProtectedKey,
  isNativeDeviceKeyBridgeRuntime,
} from './deviceKeyNativeBridge';
import {
  createDeviceKeyMissingError,
  createDeviceKeyUnavailableError,
  requiresDeviceKey,
  type VaultProtectionMode,
} from './deviceKeyProtectionPolicy';
import { isLocalSecretStoreSupported } from '@/platform/localSecretStore';

export interface RequiredDeviceKeyResult {
  deviceKey: Uint8Array | null;
  deviceKeyAvailable: boolean;
  error: Error | null;
}

export interface ResolveRequiredDeviceKeyInput {
  userId: string | null | undefined;
  vaultProtectionMode: VaultProtectionMode;
  cachedDeviceKey: Uint8Array | null;
  loadDeviceKey: (userId: string) => Promise<Uint8Array | null>;
  hasDeviceKey: (userId: string) => Promise<boolean>;
}

export async function resolveRequiredDeviceKey(
  input: ResolveRequiredDeviceKeyInput,
): Promise<RequiredDeviceKeyResult> {
  const { userId, vaultProtectionMode, cachedDeviceKey, loadDeviceKey, hasDeviceKey } = input;

  if (requiresDeviceKey(vaultProtectionMode) && !(await isLocalSecretStoreSupported())) {
    return {
      deviceKey: null,
      deviceKeyAvailable: false,
      error: createDeviceKeyUnavailableError(),
    };
  }

  if (isNativeDeviceKeyBridgeRuntime() && userId) {
    const deviceKeyAvailable = await hasDeviceKey(userId);
    if (requiresDeviceKey(vaultProtectionMode) && !deviceKeyAvailable) {
      return {
        deviceKey: null,
        deviceKeyAvailable,
        error: createDeviceKeyMissingError(),
      };
    }

    return {
      deviceKey: null,
      deviceKeyAvailable,
      error: null,
    };
  }

  let deviceKey = cachedDeviceKey;
  if (!deviceKey && userId) {
    deviceKey = await loadDeviceKey(userId);
  }

  if (requiresDeviceKey(vaultProtectionMode) && !deviceKey) {
    return {
      deviceKey: null,
      deviceKeyAvailable: false,
      error: createDeviceKeyMissingError(),
    };
  }

  return {
    deviceKey,
    deviceKeyAvailable: deviceKey !== null,
    error: null,
  };
}

export async function deriveVaultKdfOutputWithDeviceKey(input: {
  masterPassword: string;
  salt: string;
  kdfVersion: number;
  userId: string | null | undefined;
  deviceKey: Uint8Array | null;
  deviceKeyAvailable: boolean;
}): Promise<Uint8Array> {
  const { masterPassword, salt, kdfVersion, userId, deviceKey, deviceKeyAvailable } = input;

  if (isNativeDeviceKeyBridgeRuntime() && deviceKeyAvailable && userId) {
    const argon2Output = await deriveRawKey(masterPassword, salt, kdfVersion);
    try {
      return await deriveNativeDeviceProtectedKey(userId, argon2Output);
    } finally {
      argon2Output.fill(0);
    }
  }

  return deriveRawKey(masterPassword, salt, kdfVersion, deviceKey || undefined);
}
