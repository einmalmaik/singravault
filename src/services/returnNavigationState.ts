import type { Location } from 'react-router-dom';

import { isDesktopAppShell } from '@/platform/appShell';

export interface ReturnNavigationState {
  returnTo?: string;
  desktopBackTo?: string;
}

export function buildReturnPath(location: Pick<Location, 'pathname' | 'search' | 'hash'>): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

export function createReturnState(returnTo: string): ReturnNavigationState {
  return {
    returnTo,
    desktopBackTo: returnTo,
  };
}

export function buildReturnState(
  location: Pick<Location, 'pathname' | 'search' | 'hash'>,
): ReturnNavigationState {
  return createReturnState(buildReturnPath(location));
}

export function resolveReturnPath(
  state: unknown,
  fallbackPath: string,
): string {
  if (!state || typeof state !== 'object') {
    return fallbackPath;
  }

  const candidate = state as ReturnNavigationState;
  if (typeof candidate.returnTo === 'string' && candidate.returnTo.length > 0) {
    return candidate.returnTo;
  }

  if (typeof candidate.desktopBackTo === 'string' && candidate.desktopBackTo.length > 0) {
    return candidate.desktopBackTo;
  }

  return fallbackPath;
}

export function getSettingsReturnFallbackPath(): string {
  return isDesktopAppShell() ? '/vault/settings' : '/settings';
}
