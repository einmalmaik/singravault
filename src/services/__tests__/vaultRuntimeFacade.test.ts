import { describe, expect, it, vi } from 'vitest';

import {
  clearVaultSessionMarkers,
  markVaultSessionActive,
  VAULT_SESSION_STORAGE_KEYS,
} from '../vaultRuntimeFacade';

describe('vaultRuntimeFacade', () => {
  it('marks and clears only vault session markers', () => {
    const storage = {
      setItem: vi.fn(),
      removeItem: vi.fn(),
    };

    markVaultSessionActive(storage, 123);
    clearVaultSessionMarkers(storage);

    expect(storage.setItem).toHaveBeenCalledWith(VAULT_SESSION_STORAGE_KEYS.sessionKey, 'active');
    expect(storage.setItem).toHaveBeenCalledWith(VAULT_SESSION_STORAGE_KEYS.timestampKey, '123');
    expect(storage.removeItem).toHaveBeenCalledWith(VAULT_SESSION_STORAGE_KEYS.sessionKey);
    expect(storage.removeItem).toHaveBeenCalledWith(VAULT_SESSION_STORAGE_KEYS.timestampKey);
    expect(storage.removeItem).toHaveBeenCalledWith(VAULT_SESSION_STORAGE_KEYS.passwordHintKey);
  });
});
