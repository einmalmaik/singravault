// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { getTauriInvoke } from "@/platform/tauriInvoke";

type StorageValue = string | null;
type StorageReturn<T> = T | Promise<T>;

export interface AuthStorage {
  getItem: (key: string) => StorageReturn<StorageValue>;
  setItem: (key: string, value: string) => StorageReturn<void>;
  removeItem: (key: string) => StorageReturn<void>;
}

const PKCE_VERIFIER_SUFFIX = "-code-verifier";
const PKCE_VERIFIER_CREATED_AT_SUFFIX = "-created-at";
const PKCE_VERIFIER_MAX_AGE_MS = 10 * 60 * 1000;

export function createAuthStorage(): AuthStorage {
  const memoryStore = new Map<string, string>();

  return {
    getItem: async (key) => {
      if (memoryStore.has(key)) {
        return memoryStore.get(key) ?? null;
      }

      const verifier = await readPkceVerifier(key);
      if (verifier) {
        memoryStore.set(key, verifier);
      }

      return verifier;
    },
    setItem: async (key, value) => {
      memoryStore.set(key, value);
      await writePkceVerifier(key, value);
    },
    removeItem: async (key) => {
      memoryStore.delete(key);
      await removePkceVerifier(key);
    },
  };
}

export function isPkceVerifierStorageKey(key: string): boolean {
  return key.endsWith(PKCE_VERIFIER_SUFFIX);
}

async function readPkceVerifier(key: string): Promise<StorageValue> {
  if (!isPkceVerifierStorageKey(key)) {
    return null;
  }

  const sessionValue = withWebStorage("sessionStorage", (storage) => storage.getItem(key));
  if (sessionValue) {
    return sessionValue;
  }

  if (isPkceVerifierExpired(key)) {
    await removePkceVerifier(key);
    return null;
  }

  const localValue = withWebStorage("localStorage", (storage) => storage.getItem(key));
  if (localValue) {
    return localValue;
  }

  return loadNativePkceVerifier(key);
}

async function writePkceVerifier(key: string, value: string): Promise<void> {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  const createdAt = Date.now().toString();
  forEachPkceStorage((storage) => {
    storage.setItem(key, value);
    storage.setItem(getPkceVerifierCreatedAtKey(key), createdAt);
  });
  await saveNativePkceVerifier(key, value);
}

async function removePkceVerifier(key: string): Promise<void> {
  if (!isPkceVerifierStorageKey(key)) {
    return;
  }

  forEachPkceStorage((storage) => {
    storage.removeItem(key);
    storage.removeItem(getPkceVerifierCreatedAtKey(key));
  });
  await clearNativePkceVerifier(key);
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

async function saveNativePkceVerifier(key: string, verifier: string): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return;
  }

  try {
    await invoke<void>("save_pkce_verifier", { key, verifier });
  } catch {
    // Web storage fallback remains available when native keychain access fails.
  }
}

async function loadNativePkceVerifier(key: string): Promise<StorageValue> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return null;
  }

  try {
    return await invoke<string | null>("load_pkce_verifier", { key }) ?? null;
  } catch {
    return null;
  }
}

async function clearNativePkceVerifier(key: string): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return;
  }

  try {
    await invoke<void>("clear_pkce_verifier", { key });
  } catch {
    // Removing from Web storage is enough to keep the browser session clean.
  }
}
