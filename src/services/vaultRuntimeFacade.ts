export interface VaultSessionStorageKeys {
  sessionKey: string;
  timestampKey: string;
  passwordHintKey: string;
}

export const VAULT_SESSION_STORAGE_KEYS: VaultSessionStorageKeys = {
  sessionKey: 'singra_session',
  timestampKey: 'singra_session_ts',
  passwordHintKey: 'singra_session_hint',
};

export function markVaultSessionActive(
  storage: Pick<Storage, 'setItem'>,
  nowMs: number = Date.now(),
  keys: VaultSessionStorageKeys = VAULT_SESSION_STORAGE_KEYS,
): void {
  storage.setItem(keys.sessionKey, 'active');
  storage.setItem(keys.timestampKey, nowMs.toString());
}

export function clearVaultSessionMarkers(
  storage: Pick<Storage, 'removeItem'>,
  keys: VaultSessionStorageKeys = VAULT_SESSION_STORAGE_KEYS,
): void {
  storage.removeItem(keys.sessionKey);
  storage.removeItem(keys.timestampKey);
  storage.removeItem(keys.passwordHintKey);
}
