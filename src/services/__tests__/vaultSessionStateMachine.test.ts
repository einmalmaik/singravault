import { describe, expect, it } from 'vitest';

import {
  assertVaultSessionTransitionAllowed,
  deriveVaultSessionState,
} from '../vaultSessionStateMachine';

const base = {
  authReady: true,
  authLoading: false,
  hasUser: true,
  vaultLoading: false,
  vaultUnlocked: false,
  requiresTwoFactor: false,
  requiresDeviceKey: false,
  hasError: false,
};

describe('vaultSessionStateMachine', () => {
  it('keeps Device Key, 2FA, quarantine and integrity states separate', () => {
    expect(deriveVaultSessionState({ ...base, requiresDeviceKey: true })).toBe('requires_device_key');
    expect(deriveVaultSessionState({ ...base, requiresTwoFactor: true })).toBe('requires_2fa');
    expect(deriveVaultSessionState({ ...base, hasItemQuarantine: true })).toBe('item_quarantine');
    expect(deriveVaultSessionState({ ...base, integrityBlocked: true })).toBe('integrity_blocked');
  });

  it('models lock and logout transitions explicitly', () => {
    expect(deriveVaultSessionState({ ...base, event: 'vault_lock' })).toBe('vault_locked');
    expect(deriveVaultSessionState({ ...base, event: 'logout' })).toBe('anonymous');
  });

  it('allows unlock to fail into typed security states', () => {
    expect(assertVaultSessionTransitionAllowed('vault_unlocking', 'requires_device_key')).toBe(true);
    expect(assertVaultSessionTransitionAllowed('vault_unlocking', 'requires_2fa')).toBe(true);
    expect(assertVaultSessionTransitionAllowed('vault_unlocking', 'integrity_blocked')).toBe(true);
  });
});
