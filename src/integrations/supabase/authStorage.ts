// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { clearPkceVerifier, loadPkceVerifier, savePkceVerifier } from "@/platform/pkceVerifierStore";
import { isTauriRuntime } from "@/platform/runtime";

type StorageValue = string | null;
type StorageReturn<T> = T | Promise<T>;

export interface AuthStorage {
  getItem: (key: string) => StorageReturn<StorageValue>;
  setItem: (key: string, value: string) => StorageReturn<void>;
  removeItem: (key: string) => StorageReturn<void>;
}

const PKCE_VERIFIER_SUFFIX = "-code-verifier";

export function createAuthStorage(): AuthStorage {
  const memoryStore = new Map<string, string>();
  // Desktop builds need a restart-safe Supabase session snapshot because the
  // WebView process is fully torn down between launches. Web/PWA keep using
  // the stricter BFF/keychain lifecycle outside this adapter.
  const shouldPersistDesktopSession = isTauriRuntime();

  return {
    getItem: async (key) => {
      if (memoryStore.has(key)) {
        return memoryStore.get(key) ?? null;
      }

      const verifier = isPkceVerifierStorageKey(key) ? await loadPkceVerifier(key) : null;
      if (verifier) {
        memoryStore.set(key, verifier);
        return verifier;
      }

      if (shouldPersistDesktopSession) {
        const desktopSessionValue = readDesktopSessionValue(key);
        if (desktopSessionValue !== null) {
          memoryStore.set(key, desktopSessionValue);
          return desktopSessionValue;
        }
      }

      return null;
    },
    setItem: async (key, value) => {
      memoryStore.set(key, value);
      if (isPkceVerifierStorageKey(key)) {
        await savePkceVerifier(key, value);
        return;
      }

      if (shouldPersistDesktopSession) {
        writeDesktopSessionValue(key, value);
      }
    },
    removeItem: async (key) => {
      memoryStore.delete(key);
      if (isPkceVerifierStorageKey(key)) {
        await clearPkceVerifier(key);
        return;
      }

      if (shouldPersistDesktopSession) {
        removeDesktopSessionValue(key);
      }
    },
  };
}

export function isPkceVerifierStorageKey(key: string): boolean {
  return key.endsWith(PKCE_VERIFIER_SUFFIX);
}

function readDesktopSessionValue(key: string): StorageValue {
  if (typeof window === "undefined") {
    return null;
  }

  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeDesktopSessionValue(key: string, value: string): void {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Desktop auth still has the in-memory + keychain path if local persistence fails.
  }
}

function removeDesktopSessionValue(key: string): void {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.removeItem(key);
  } catch {
    // Best-effort cleanup only.
  }
}
