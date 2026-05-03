import { describe, expect, it, beforeEach } from 'vitest';
import {
  DEFAULT_AUTO_LOCK_TIMEOUT,
  getInitialAutoLockTimeout,
  isStoredVaultSessionValid,
  persistAutoLockTimeoutIfAllowed,
  wipeRuntimeDeviceKey,
} from '../vaultRuntimeCleanupService';
import { VAULT_SESSION_STORAGE_KEYS } from '../vaultRuntimeFacade';

describe('vaultRuntimeCleanupService', () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('keeps auto-lock timeout ephemeral without optional cookie consent', () => {
    persistAutoLockTimeoutIfAllowed(1234);
    expect(localStorage.getItem('singra_autolock')).toBeNull();
    expect(getInitialAutoLockTimeout()).toBe(DEFAULT_AUTO_LOCK_TIMEOUT);
  });

  it('persists and restores auto-lock timeout only with optional consent', () => {
    localStorage.setItem('singra-cookie-consent', JSON.stringify({ necessary: true, optional: true }));
    persistAutoLockTimeoutIfAllowed(1234);
    expect(localStorage.getItem('singra_autolock')).toBe('1234');
    expect(getInitialAutoLockTimeout()).toBe(1234);
  });

  it('validates session markers against the configured timeout', () => {
    localStorage.setItem('singra-cookie-consent', JSON.stringify({ necessary: true, optional: true }));
    localStorage.setItem('singra_autolock', '1000');
    sessionStorage.setItem(VAULT_SESSION_STORAGE_KEYS.sessionKey, 'active');
    sessionStorage.setItem(VAULT_SESSION_STORAGE_KEYS.timestampKey, '5000');

    expect(isStoredVaultSessionValid({ nowMs: 5500 })).toBe(true);
    expect(isStoredVaultSessionValid({ nowMs: 7001 })).toBe(false);
  });

  it('wipes browser-held Device Key bytes in place', () => {
    const key = new Uint8Array([1, 2, 3]);
    wipeRuntimeDeviceKey(key);
    expect([...key]).toEqual([0, 0, 0]);
  });
});
