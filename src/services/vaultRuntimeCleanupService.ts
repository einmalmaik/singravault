import { hasOptionalCookieConsent } from '@/lib/cookieConsent';
import {
  VAULT_SESSION_STORAGE_KEYS,
  clearVaultSessionMarkers,
} from '@/services/vaultRuntimeFacade';

export const DEFAULT_AUTO_LOCK_TIMEOUT = 15 * 60 * 1000;

export function getInitialAutoLockTimeout(
  storage: Pick<Storage, 'getItem'> = localStorage,
): number {
  if (!hasOptionalCookieConsent()) {
    return DEFAULT_AUTO_LOCK_TIMEOUT;
  }

  const saved = storage.getItem('singra_autolock');
  return saved ? parseInt(saved, 10) : DEFAULT_AUTO_LOCK_TIMEOUT;
}

export function isStoredVaultSessionValid(input?: {
  sessionStorage?: Pick<Storage, 'getItem'>;
  localStorage?: Pick<Storage, 'getItem'>;
  nowMs?: number;
}): boolean {
  const sessionStore = input?.sessionStorage ?? sessionStorage;
  const localStore = input?.localStorage ?? localStorage;
  const sessionData = sessionStore.getItem(VAULT_SESSION_STORAGE_KEYS.sessionKey);
  const timestamp = sessionStore.getItem(VAULT_SESSION_STORAGE_KEYS.timestampKey);
  const timeout = getInitialAutoLockTimeout(localStore);

  if (!sessionData || !timestamp) {
    return false;
  }

  if (timeout === 0) {
    return true;
  }

  const elapsed = (input?.nowMs ?? Date.now()) - parseInt(timestamp, 10);
  return elapsed < timeout;
}

export function persistAutoLockTimeoutIfAllowed(
  timeout: number,
  storage: Pick<Storage, 'getItem' | 'setItem'> = localStorage,
): void {
  const consent = storage.getItem('singra-cookie-consent');
  if (!consent) {
    return;
  }

  try {
    const parsed = JSON.parse(consent) as { optional?: unknown };
    if (parsed.optional) {
      storage.setItem('singra_autolock', timeout.toString());
    }
  } catch {
    // If consent cannot be parsed, fail closed and do not persist preferences.
  }
}

export function wipeRuntimeDeviceKey(deviceKey: Uint8Array | null): void {
  deviceKey?.fill(0);
}

export function clearRuntimeSessionMarkers(
  storage: Pick<Storage, 'removeItem'> = sessionStorage,
): void {
  clearVaultSessionMarkers(storage);
}
