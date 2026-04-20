// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { clearPkceVerifier, loadPkceVerifier, savePkceVerifier } from "@/platform/pkceVerifierStore";

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

  return {
    getItem: async (key) => {
      if (memoryStore.has(key)) {
        return memoryStore.get(key) ?? null;
      }

      const verifier = isPkceVerifierStorageKey(key) ? await loadPkceVerifier(key) : null;
      if (verifier) {
        memoryStore.set(key, verifier);
      }

      return verifier;
    },
    setItem: async (key, value) => {
      memoryStore.set(key, value);
      if (isPkceVerifierStorageKey(key)) {
        await savePkceVerifier(key, value);
      }
    },
    removeItem: async (key) => {
      memoryStore.delete(key);
      if (isPkceVerifierStorageKey(key)) {
        await clearPkceVerifier(key);
      }
    },
  };
}

export function isPkceVerifierStorageKey(key: string): boolean {
  return key.endsWith(PKCE_VERIFIER_SUFFIX);
}
