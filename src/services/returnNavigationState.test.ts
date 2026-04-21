import { describe, expect, it } from 'vitest';

import {
  buildReturnPath,
  buildReturnState,
  createReturnState,
  getSettingsReturnFallbackPath,
  resolveReturnPath,
} from '@/services/returnNavigationState';

describe('returnNavigationState', () => {
  it('builds a stable return path from location parts', () => {
    expect(buildReturnPath({
      pathname: '/vault/settings',
      search: '?tab=security',
      hash: '#passkeys',
    })).toBe('/vault/settings?tab=security#passkeys');
  });

  it('creates backward-compatible return state entries', () => {
    expect(buildReturnState({
      pathname: '/settings',
      search: '?tab=data-legal',
      hash: '',
    })).toEqual({
      returnTo: '/settings?tab=data-legal',
      desktopBackTo: '/settings?tab=data-legal',
    });
  });

  it('prefers generic returnTo but falls back to legacy desktopBackTo', () => {
    expect(resolveReturnPath(createReturnState('/vault'), '/settings')).toBe('/vault');
    expect(resolveReturnPath({ desktopBackTo: '/legacy' }, '/settings')).toBe('/legacy');
    expect(resolveReturnPath(null, '/settings')).toBe('/settings');
  });

  it('uses the web fallback when no desktop runtime is present', () => {
    expect(getSettingsReturnFallbackPath()).toBe('/settings');
  });
});
