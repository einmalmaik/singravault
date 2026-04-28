import { isTauriRuntime } from '@/platform/runtime';

export const VAULT_PROTECTION_MODE_MASTER_ONLY = 'master_only';
export const VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED = 'device_key_required';

export type VaultProtectionMode =
    | typeof VAULT_PROTECTION_MODE_MASTER_ONLY
    | typeof VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED;

export type DeviceKeyUnlockErrorCode =
    | 'DEVICE_KEY_REQUIRED_BUT_MISSING'
    | 'DEVICE_KEY_REQUIRED_BUT_INVALID'
    | 'DEVICE_KEY_STORE_UNAVAILABLE'
    | 'USER_KEY_MIGRATION_REQUIRED'
    | 'MASTER_PASSWORD_INVALID'
    | 'VAULT_KEY_DECRYPT_FAILED';

export class DeviceKeyUnlockError extends Error {
    code: DeviceKeyUnlockErrorCode;

    constructor(code: DeviceKeyUnlockErrorCode, message: string) {
        super(message);
        this.name = 'DeviceKeyUnlockError';
        this.code = code;
    }
}

export function normalizeVaultProtectionMode(value: unknown): VaultProtectionMode {
    return value === VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED
        ? VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED
        : VAULT_PROTECTION_MODE_MASTER_ONLY;
}

export function requiresDeviceKey(mode: VaultProtectionMode): boolean {
    return mode === VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED;
}

export function createDeviceKeyMissingError(): DeviceKeyUnlockError {
    return new DeviceKeyUnlockError(
        'DEVICE_KEY_REQUIRED_BUT_MISSING',
        'This vault is protected with a Device Key. No matching Device Key was found on this device. Import your Device Key from a trusted device or use your documented recovery process. Without the Device Key, this vault cannot be decrypted.',
    );
}

export function createDeviceKeyUnavailableError(): DeviceKeyUnlockError {
    const runtimeDetail = isTauriRuntime()
        ? 'The OS keychain is not reachable. Check your operating-system login or import the Device Key again if the keychain was reset.'
        : 'The local browser secret store is unavailable or was reset. Import the Device Key again for Device-Key-protected vaults.';

    return new DeviceKeyUnlockError(
        'DEVICE_KEY_STORE_UNAVAILABLE',
        runtimeDetail,
    );
}

export function createDeviceKeyInvalidError(): DeviceKeyUnlockError {
    return new DeviceKeyUnlockError(
        'DEVICE_KEY_REQUIRED_BUT_INVALID',
        'The local Device Key does not match this vault, or the master password is incorrect. Check your master password or import the correct Device Key again.',
    );
}

export function createUserKeyMigrationRequiredError(): DeviceKeyUnlockError {
    return new DeviceKeyUnlockError(
        'USER_KEY_MIGRATION_REQUIRED',
        'Device Key protection requires the vault UserKey wrapper to be saved first. Unlock online once and retry after the migration completes.',
    );
}

export function createMasterPasswordInvalidError(): DeviceKeyUnlockError {
    return new DeviceKeyUnlockError(
        'MASTER_PASSWORD_INVALID',
        'Invalid master password',
    );
}
