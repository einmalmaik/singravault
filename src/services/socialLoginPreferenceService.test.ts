import { beforeEach, describe, expect, it } from 'vitest';

import {
  clearLastOAuthProvider,
  hasSeenAuthScreen,
  markAuthScreenSeen,
  readLastOAuthProvider,
  rememberLastOAuthProvider,
} from './socialLoginPreferenceService';

describe('socialLoginPreferenceService', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('stores only the OAuth provider id locally', () => {
    rememberLastOAuthProvider('github');

    expect(readLastOAuthProvider()).toBe('github');
    expect(localStorage.getItem('singra:last-oauth-provider')).toBe('github');
  });

  it('ignores unsupported stored provider values', () => {
    localStorage.setItem('singra:last-oauth-provider', 'email');

    expect(readLastOAuthProvider()).toBeNull();
  });

  it('clears the local provider hint on account deletion cleanup', () => {
    rememberLastOAuthProvider('google');
    clearLastOAuthProvider();

    expect(readLastOAuthProvider()).toBeNull();
  });

  it('tracks whether the auth screen was seen without account data', () => {
    expect(hasSeenAuthScreen()).toBe(false);

    markAuthScreenSeen();

    expect(hasSeenAuthScreen()).toBe(true);
    expect(localStorage.getItem('singra:auth-screen-seen')).toBe('1');
  });
});
