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
const SUPABASE_HOST_SEGMENT = ".supabase.";
const SUPABASE_AUTH_TOKEN_KEY_PATTERN = /^sb-[a-z0-9]+-auth-token$/i;

export function createAuthStorage(): AuthStorage {
  const memoryStore = new Map<string, string>();
  if (isTauriRuntime()) {
    purgeLegacyDesktopAuthTokens();
  }

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

      return null;
    },
    setItem: async (key, value) => {
      memoryStore.set(key, value);
      if (isPkceVerifierStorageKey(key)) {
        await savePkceVerifier(key, value);
        return;
      }

    },
    removeItem: async (key) => {
      memoryStore.delete(key);
      if (isPkceVerifierStorageKey(key)) {
        await clearPkceVerifier(key);
        return;
      }

    },
  };
}

export function isPkceVerifierStorageKey(key: string): boolean {
  return key.endsWith(PKCE_VERIFIER_SUFFIX);
}

export function getDesktopSessionStorageKey(supabaseUrl: string): string | null {
  const normalizedUrl = supabaseUrl.trim();
  if (!normalizedUrl) {
    return null;
  }

  try {
    const hostname = new URL(normalizedUrl).hostname.toLowerCase();
    const hostSeparatorIndex = hostname.indexOf(SUPABASE_HOST_SEGMENT);
    if (hostSeparatorIndex <= 0) {
      return null;
    }

    const projectRef = hostname.slice(0, hostSeparatorIndex);
    return projectRef ? `sb-${projectRef}-auth-token` : null;
  } catch {
    return null;
  }
}

export function purgeLegacyDesktopAuthTokens(supabaseUrl?: string): number {
  if (typeof window === "undefined") {
    return 0;
  }

  let removed = 0;
  const exactSessionKey = supabaseUrl ? getDesktopSessionStorageKey(supabaseUrl) : null;

  try {
    const keysToRemove = new Set<string>();
    if (exactSessionKey) {
      keysToRemove.add(exactSessionKey);
    }

    for (let index = 0; index < window.localStorage.length; index += 1) {
      const key = window.localStorage.key(index);
      if (key && isSupabaseAuthTokenStorageKey(key)) {
        keysToRemove.add(key);
      }
    }

    keysToRemove.forEach((key) => {
      window.localStorage.removeItem(key);
      removed += 1;
    });
  } catch (error) {
    console.warn("[AuthStorage] Failed to purge legacy desktop auth tokens from localStorage.", {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  return removed;
}

export function readDesktopPersistedSessionTokens(
  supabaseUrl: string,
): null {
  const sessionKey = getDesktopSessionStorageKey(supabaseUrl);
  if (!sessionKey) {
    return null;
  }

  // Legacy versions stored full Supabase sessions in localStorage. Never use
  // those tokens for recovery; delete them and force keychain-backed refresh.
  clearDesktopPersistedSessionTokens(supabaseUrl);
  return null;
}

export function clearDesktopPersistedSessionTokens(supabaseUrl: string): void {
  purgeLegacyDesktopAuthTokens(supabaseUrl);
}

function isSupabaseAuthTokenStorageKey(key: string): boolean {
  return SUPABASE_AUTH_TOKEN_KEY_PATTERN.test(key);
}
