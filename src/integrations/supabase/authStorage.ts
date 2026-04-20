// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

type StorageValue = string | null;

export interface AuthStorage {
  getItem: (key: string) => StorageValue;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
}

const PKCE_VERIFIER_SUFFIX = "-code-verifier";

export function createAuthStorage(): AuthStorage {
  const memoryStore = new Map<string, string>();

  return {
    getItem: (key) => {
      if (memoryStore.has(key)) {
        return memoryStore.get(key) ?? null;
      }

      const verifier = readPkceVerifier(key);
      if (verifier) {
        memoryStore.set(key, verifier);
      }

      return verifier;
    },
    setItem: (key, value) => {
      memoryStore.set(key, value);
      writePkceVerifier(key, value);
    },
    removeItem: (key) => {
      memoryStore.delete(key);
      removePkceVerifier(key);
    },
  };
}

export function isPkceVerifierStorageKey(key: string): boolean {
  return key.endsWith(PKCE_VERIFIER_SUFFIX);
}

function readPkceVerifier(key: string): StorageValue {
  if (!isPkceVerifierStorageKey(key)) {
    return null;
  }

  return withSessionStorage((storage) => storage.getItem(key));
}

function writePkceVerifier(key: string, value: string): void {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  withSessionStorage((storage) => {
    storage.setItem(key, value);
  });
}

function removePkceVerifier(key: string): void {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  withSessionStorage((storage) => {
    storage.removeItem(key);
  });
}

function withSessionStorage<T>(action: (storage: Storage) => T): T | null {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return action(window.sessionStorage);
  } catch {
    return null;
  }
}
