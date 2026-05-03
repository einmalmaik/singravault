import { DeviceKeyUnlockError } from './deviceKeyProtectionPolicy';
import type { VaultIntegrityBlockedReason } from './vaultIntegrityService';

export type VaultUiErrorCode =
  | 'vault_not_setup'
  | 'too_many_attempts'
  | 'master_password_invalid'
  | 'device_key_missing'
  | 'device_key_invalid'
  | 'device_key_unavailable'
  | 'two_factor_required'
  | 'two_factor_failed'
  | 'two_factor_unavailable'
  | 'passkey_cancelled'
  | 'passkey_unsupported'
  | 'passkey_failed'
  | 'integrity_blocked'
  | 'item_quarantined'
  | 'vault_snapshot_unavailable'
  | 'unknown';

export interface VaultUiSafeError {
  code: VaultUiErrorCode;
  message: string;
}

export function mapVaultErrorToUiSafeError(error: unknown): VaultUiSafeError {
  const message = error instanceof Error ? error.message : String(error ?? '');

  if (error instanceof DeviceKeyUnlockError || message.includes('Device Key')) {
    if (message.toLowerCase().includes('missing')) {
      return { code: 'device_key_missing', message: 'Device Key is required on this device.' };
    }
    if (message.toLowerCase().includes('unavailable') || message.toLowerCase().includes('not available')) {
      return { code: 'device_key_unavailable', message: 'Secure local secret storage is not available.' };
    }
    return { code: 'device_key_invalid', message: 'Device Key verification failed.' };
  }

  if (message.includes('Vault 2FA verification required')) {
    return { code: 'two_factor_required', message: 'Vault 2FA verification is required.' };
  }
  if (message.includes('Vault 2FA verification failed')) {
    return { code: 'two_factor_failed', message: 'Vault 2FA verification failed.' };
  }
  if (message.includes('Vault 2FA status')) {
    return { code: 'two_factor_unavailable', message: 'Vault 2FA status is unavailable.' };
  }

  if (message.includes('Passkey authentication was cancelled')) {
    return { code: 'passkey_cancelled', message: 'Passkey authentication was cancelled.' };
  }
  if (message.includes('no PRF') || message.includes('does not support vault unlock')) {
    return { code: 'passkey_unsupported', message: 'This passkey does not support vault unlock.' };
  }
  if (message.includes('Passkey')) {
    return { code: 'passkey_failed', message: 'Passkey unlock failed.' };
  }

  if (message.includes('quarantined')) {
    return { code: 'item_quarantined', message: 'This vault item is quarantined.' };
  }
  if (message.includes('Integrit') || message.includes('integrity')) {
    return { code: 'integrity_blocked', message: 'Vault integrity verification failed.' };
  }
  if (message.includes('Vault snapshot unavailable')) {
    return { code: 'vault_snapshot_unavailable', message: 'Vault snapshot unavailable.' };
  }
  if (message.includes('Invalid master password')) {
    return { code: 'master_password_invalid', message: 'Invalid master password.' };
  }
  if (message.includes('Vault not set up')) {
    return { code: 'vault_not_setup', message: 'Vault is not set up.' };
  }
  if (message.includes('Too many attempts')) {
    return { code: 'too_many_attempts', message };
  }

  return { code: 'unknown', message: 'Vault operation failed.' };
}

export function mapIntegrityBlockedReasonToUiSafeError(
  reason: VaultIntegrityBlockedReason | null | undefined,
): VaultUiSafeError {
  return {
    code: 'integrity_blocked',
    message: reason
      ? `Vault integrity verification failed (${reason}).`
      : 'Vault integrity verification failed.',
  };
}
