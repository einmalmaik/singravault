// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

type StorageValue = string | null;

export interface AuthStorage {
  getItem: (key: string) => StorageValue;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
}

const PKCE_VERIFIER_SUFFIX = "-code-verifier";
const PKCE_VERIFIER_CREATED_AT_SUFFIX = "-created-at";
const PKCE_VERIFIER_MAX_AGE_MS = 10 * 60 * 1000;

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

  const sessionValue = withWebStorage("sessionStorage", (storage) => storage.getItem(key));
  if (sessionValue) {
    return sessionValue;
  }

  if (isPkceVerifierExpired(key)) {
    removePkceVerifier(key);
    return null;
  }

  return withWebStorage("localStorage", (storage) => storage.getItem(key));
}

function writePkceVerifier(key: string, value: string): void {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  const createdAt = Date.now().toString();
  forEachPkceStorage((storage) => {
    storage.setItem(key, value);
    storage.setItem(getPkceVerifierCreatedAtKey(key), createdAt);
  });
}

function removePkceVerifier(key: string): void {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  forEachPkceStorage((storage) => {
    storage.removeItem(key);
    storage.removeItem(getPkceVerifierCreatedAtKey(key));
  });
}

function isPkceVerifierExpired(key: string): boolean {
  const rawCreatedAt = withWebStorage("localStorage", (storage) => (
    storage.getItem(getPkceVerifierCreatedAtKey(key))
  ));

  if (!rawCreatedAt) {
    return false;
  }

  const createdAt = Number.parseInt(rawCreatedAt, 10);
  return Number.isNaN(createdAt) || Date.now() - createdAt > PKCE_VERIFIER_MAX_AGE_MS;
}

function getPkceVerifierCreatedAtKey(key: string): string {
  return `${key}${PKCE_VERIFIER_CREATED_AT_SUFFIX}`;
}

function forEachPkceStorage(action: (storage: Storage) => void): void {
  withWebStorage("sessionStorage", action);
  withWebStorage("localStorage", action);
}

function withWebStorage<T>(
  storageName: "localStorage" | "sessionStorage",
  action: (storage: Storage) => T,
): T | null {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return action(window[storageName]);
  } catch {
    return null;
  }
}
