import { describe, expect, it } from 'vitest';

import { deriveDeviceKeyState } from '../deviceKeyStateMachine';

describe('deviceKeyStateMachine', () => {
  it('keeps master-only vaults out of the Device Key flow', () => {
    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'master_only',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: false,
    })).toBe('not_configured');
  });

  it('requires import or recovery when a protected vault has no local key', () => {
    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'device_key_required',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: false,
    })).toBe('import_required');

    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'device_key_required',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: false,
      authenticatedButLocked: true,
    })).toBe('active_but_missing_on_this_device');

    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'device_key_required',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: false,
      recoveryAvailable: true,
    })).toBe('recovery_required');
  });

  it('distinguishes active local key from unlocked vault state', () => {
    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'device_key_required',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: true,
    })).toBe('active_on_this_device');

    expect(deriveDeviceKeyState({
      vaultProtectionMode: 'device_key_required',
      localSecretStoreSupported: true,
      localDeviceKeyAvailable: true,
      vaultUnlocked: true,
    })).toBe('unlocked');
  });
});
