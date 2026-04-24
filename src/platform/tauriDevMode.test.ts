// Licensed under the Business Source License 1.1 - see LICENSE

import { beforeEach, describe, expect, it } from 'vitest';

import {
  isTauriDevAuthBypassEnabled,
  isTauriDevUserId,
  TAURI_DEV_AUTH_BYPASS_STORAGE_KEY,
  TAURI_DEV_USER_ID,
} from './tauriDevMode';

function setTauriRuntimeMarker(enabled: boolean): void {
  if (enabled) {
    Object.defineProperty(window, '__TAURI_INTERNALS__', {
      value: {},
      configurable: true,
    });
    return;
  }

  Reflect.deleteProperty(window, '__TAURI_INTERNALS__');
}

describe('tauriDevMode', () => {
  beforeEach(() => {
    setTauriRuntimeMarker(false);
    window.localStorage.clear();
    window.history.replaceState(null, '', '/');
  });

  it('does not enable account bypass outside the Tauri dev runtime', () => {
    window.history.replaceState(null, '', '/?tauriDevAuth=1');

    expect(isTauriDevAuthBypassEnabled()).toBe(false);
    expect(window.localStorage.getItem(TAURI_DEV_AUTH_BYPASS_STORAGE_KEY)).toBeNull();
  });

  it('keeps Tauri dev regular accounts on the normal auth path unless bypass is requested', () => {
    setTauriRuntimeMarker(true);

    expect(isTauriDevAuthBypassEnabled()).toBe(false);
  });

  it('enables and persists account bypass from an explicit Tauri dev query flag', () => {
    setTauriRuntimeMarker(true);
    window.history.replaceState(null, '', '/?tauriDevAuth=1');

    expect(isTauriDevAuthBypassEnabled()).toBe(true);

    window.history.replaceState(null, '', '/vault');
    expect(isTauriDevAuthBypassEnabled()).toBe(true);
  });

  it('disables persisted account bypass from an explicit Tauri dev query flag', () => {
    setTauriRuntimeMarker(true);
    window.localStorage.setItem(TAURI_DEV_AUTH_BYPASS_STORAGE_KEY, '1');
    window.history.replaceState(null, '', '/?tauriDevAuth=0');

    expect(isTauriDevAuthBypassEnabled()).toBe(false);
    expect(window.localStorage.getItem(TAURI_DEV_AUTH_BYPASS_STORAGE_KEY)).toBeNull();
  });

  it('identifies only the dedicated Tauri dev user ID as the local test identity', () => {
    expect(isTauriDevUserId(TAURI_DEV_USER_ID)).toBe(true);
    expect(isTauriDevUserId('regular-user-id')).toBe(false);
    expect(isTauriDevUserId(null)).toBe(false);
  });
});
