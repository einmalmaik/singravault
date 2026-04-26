import type { DesktopOAuthProvider } from '@/platform/desktopOAuth';

const LAST_OAUTH_PROVIDER_KEY = 'singra:last-oauth-provider';
const AUTH_SCREEN_SEEN_KEY = 'singra:auth-screen-seen';

const SUPPORTED_OAUTH_PROVIDERS = new Set<DesktopOAuthProvider>(['google', 'github', 'discord']);

export function readLastOAuthProvider(): DesktopOAuthProvider | null {
  if (typeof window === 'undefined') {
    return null;
  }

  const provider = window.localStorage.getItem(LAST_OAUTH_PROVIDER_KEY) as DesktopOAuthProvider | null;
  return provider && SUPPORTED_OAUTH_PROVIDERS.has(provider) ? provider : null;
}

export function rememberLastOAuthProvider(provider: DesktopOAuthProvider): void {
  if (typeof window === 'undefined' || !SUPPORTED_OAUTH_PROVIDERS.has(provider)) {
    return;
  }

  window.localStorage.setItem(LAST_OAUTH_PROVIDER_KEY, provider);
}

export function clearLastOAuthProvider(): void {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.removeItem(LAST_OAUTH_PROVIDER_KEY);
}

export function hasSeenAuthScreen(): boolean {
  if (typeof window === 'undefined') {
    return false;
  }

  return window.localStorage.getItem(AUTH_SCREEN_SEEN_KEY) === '1';
}

export function markAuthScreenSeen(): void {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.setItem(AUTH_SCREEN_SEEN_KEY, '1');
}
