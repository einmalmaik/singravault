import { isTauriRuntime } from './runtime';

export const TAURI_DEV_USER_ID = '00000000-0000-4000-8000-000000000001';
export const TAURI_DEV_USER_EMAIL = 'tauri-dev@singra.local';
export const TAURI_DEV_VAULT_ID = '00000000-0000-4000-8000-000000000002';
export const TAURI_DEV_AUTH_BYPASS_STORAGE_KEY = 'singra:tauri-dev-auth-bypass';

export function isTauriDevMode(): boolean {
  return import.meta.env.DEV && isTauriRuntime();
}

export function isTauriDevUserId(userId: string | null | undefined): boolean {
  void userId;
  return false;
}

export function isTauriDevAuthBypassEnabled(): boolean {
  disableTauriDevAuthBypass();
  return false;
}

export function disableTauriDevAuthBypass(): void {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.removeItem(TAURI_DEV_AUTH_BYPASS_STORAGE_KEY);
}
