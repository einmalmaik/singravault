import { requiresDeviceKey, type VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';

export type DeviceKeyState =
  | 'unsupported'
  | 'not_configured'
  | 'activation_in_progress'
  | 'active_on_this_device'
  | 'active_but_missing_on_this_device'
  | 'import_required'
  | 'recovery_required'
  | 'activation_failed'
  | 'unlock_failed'
  | 'unlocked';

export interface DeviceKeyStateInput {
  vaultProtectionMode: VaultProtectionMode;
  localSecretStoreSupported: boolean;
  localDeviceKeyAvailable: boolean;
  activationInProgress?: boolean;
  activationFailed?: boolean;
  unlockFailed?: boolean;
  vaultUnlocked?: boolean;
  authenticatedButLocked?: boolean;
  recoveryAvailable?: boolean;
}

export function deriveDeviceKeyState(input: DeviceKeyStateInput): DeviceKeyState {
  if (!input.localSecretStoreSupported) {
    return 'unsupported';
  }
  if (input.activationInProgress) {
    return 'activation_in_progress';
  }
  if (input.activationFailed) {
    return 'activation_failed';
  }
  if (input.unlockFailed) {
    return 'unlock_failed';
  }
  if (!requiresDeviceKey(input.vaultProtectionMode)) {
    return 'not_configured';
  }
  if (input.vaultUnlocked && input.localDeviceKeyAvailable) {
    return 'unlocked';
  }
  if (input.localDeviceKeyAvailable) {
    return 'active_on_this_device';
  }
  if (input.authenticatedButLocked) {
    return 'active_but_missing_on_this_device';
  }

  return input.recoveryAvailable ? 'recovery_required' : 'import_required';
}
