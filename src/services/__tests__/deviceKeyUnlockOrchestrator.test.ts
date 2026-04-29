import { beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveRequiredDeviceKey } from '../deviceKeyUnlockOrchestrator';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  VAULT_PROTECTION_MODE_MASTER_ONLY,
} from '../deviceKeyProtectionPolicy';

vi.mock('@/platform/localSecretStore', () => ({
  isLocalSecretStoreSupported: vi.fn(async () => true),
}));

vi.mock('../deviceKeyNativeBridge', () => ({
  deriveNativeDeviceProtectedKey: vi.fn(),
  isNativeDeviceKeyBridgeRuntime: vi.fn(() => false),
}));

describe('deviceKeyUnlockOrchestrator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not require a Device Key in master-only mode', async () => {
    const result = await resolveRequiredDeviceKey({
      userId: 'user-1',
      vaultProtectionMode: VAULT_PROTECTION_MODE_MASTER_ONLY,
      cachedDeviceKey: null,
      loadDeviceKey: vi.fn(async () => null),
      hasDeviceKey: vi.fn(async () => false),
    });

    expect(result.error).toBeNull();
    expect(result.deviceKeyAvailable).toBe(false);
  });

  it('blocks vault unlock when device_key_required has no local Device Key', async () => {
    const result = await resolveRequiredDeviceKey({
      userId: 'user-1',
      vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      cachedDeviceKey: null,
      loadDeviceKey: vi.fn(async () => null),
      hasDeviceKey: vi.fn(async () => false),
    });

    expect(result.error?.message).toContain('Device Key');
  });

  it('uses an existing cached Device Key without silently generating a new one', async () => {
    const cachedDeviceKey = new Uint8Array([1, 2, 3]);
    const loadDeviceKey = vi.fn(async () => null);

    const result = await resolveRequiredDeviceKey({
      userId: 'user-1',
      vaultProtectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
      cachedDeviceKey,
      loadDeviceKey,
      hasDeviceKey: vi.fn(async () => false),
    });

    expect(result.error).toBeNull();
    expect(result.deviceKey).toBe(cachedDeviceKey);
    expect(loadDeviceKey).not.toHaveBeenCalled();
  });
});
