import { describe, expect, it } from 'vitest';

import { canAccessAccountVaultOperation, getAccountVaultRouteRequirement } from '../accountVaultRoutePolicy';

describe('accountVaultRoutePolicy', () => {
  it('allows account settings with an account session but without vault unlock', () => {
    expect(getAccountVaultRouteRequirement('account_settings')).toBe('account_session_required');
    expect(canAccessAccountVaultOperation('account_settings', {
      hasAccountSession: true,
      isVaultUnlocked: false,
    })).toBe(true);
  });

  it('requires vault unlock for vault access and Device Key export', () => {
    expect(canAccessAccountVaultOperation('vault_view', {
      hasAccountSession: true,
      isVaultUnlocked: false,
    })).toBe(false);
    expect(canAccessAccountVaultOperation('device_key_export', {
      hasAccountSession: true,
      isVaultUnlocked: false,
    })).toBe(false);
  });

  it('allows Device Key import offer before unlock but never vault access', () => {
    expect(canAccessAccountVaultOperation('device_key_import', {
      hasAccountSession: true,
      isVaultUnlocked: false,
    })).toBe(true);
  });
});
