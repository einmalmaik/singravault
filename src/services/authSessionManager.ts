// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Central auth session lifecycle manager.
 *
 * Web/PWA use the BFF HttpOnly refresh cookie. Tauri stores only the refresh
 * token in the OS keychain via Rust commands. Access tokens stay in memory.
 */

import type { Session, User } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";
import { hasOAuthCallbackPayload } from "@/platform/tauriOAuthCallback";
import { isTauriRuntime } from "@/platform/runtime";
import { getTauriInvoke } from "@/platform/tauriInvoke";
import { runtimeConfig } from "@/config/runtimeConfig";

export const SESSION_FALLBACK_STORAGE_KEY = "singra-auth-session-fallback";
export const AUTH_OFFLINE_IDENTITY_STORAGE_KEY = "singra-auth-offline-identity";

const AUTH_STATE_DB_NAME = "singra-auth-state";
const OFFLINE_IDENTITY_STORE = "offline-identities";
const OFFLINE_IDENTITY_RECORD_KEY = "last";

export type AuthMode = "online" | "offline" | "unauthenticated";

export interface OfflineIdentity {
  userId: string;
  email: string | null;
  updatedAt: string;
}

export interface HydratedAuthState {
  mode: AuthMode;
  session: Session | null;
  user: User | null;
  offlineIdentity: OfflineIdentity | null;
}

type SessionTokens = Pick<Session, "access_token" | "refresh_token">;

let refreshInFlight: Promise<Session | null> | null = null;

export function isInIframe(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

export async function hydrateAuthSession(): Promise<HydratedAuthState> {
  const memorySession = await getMemorySession();
  if (memorySession?.access_token) {
    await persistAuthenticatedSession(memorySession);
    return onlineState(memorySession);
  }

  if (isTauriRuntime()) {
    // Check if we have incoming deep links (a login is in progress).
    // If so, do NOT attempt to refresh the old keychain token, as its failure 
    // would trigger a SIGNED_OUT event that destroys the newly applied deep link session.
    try {
      const { getInitialDeepLinks } = await import("@/platform/deepLink");
      const initialLinks = await getInitialDeepLinks();
      const hasLoginLink = initialLinks.some((url) => hasOAuthCallbackPayload(url));
      if (hasLoginLink) {
        console.info("[Auth] Incoming deep link detected, skipping keychain refresh to prevent race condition.");
        return offlineOrUnauthenticatedState();
      }
    } catch (e) {
      console.warn("Failed to check initial deep links during hydration", e);
    }

    const tauriSession = await refreshFromTauriKeychain();
    if (tauriSession) {
      return onlineState(tauriSession);
    }

    return offlineOrUnauthenticatedState();
  }

  if (isInIframe()) {
    const fallbackSession = await restoreSessionFromFallback();
    if (fallbackSession) {
      return onlineState(fallbackSession);
    }

    return offlineOrUnauthenticatedState();
  }

  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    return offlineOrUnauthenticatedState();
  }

  const bffSession = await hydrateFromBffCookie();
  if (bffSession) {
    return onlineState(bffSession);
  }

  const fallbackSession = await restoreSessionFromFallback();
  if (fallbackSession) {
    return onlineState(fallbackSession);
  }

  return offlineOrUnauthenticatedState();
}

export async function applyAuthenticatedSession(tokens: SessionTokens): Promise<Session> {
  const { data, error } = await supabase.auth.setSession({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
  });

  if (error || !data.session) {
    throw error ?? new Error("Failed to apply auth session");
  }

  await persistAuthenticatedSession(data.session);
  return data.session;
}

export async function persistAuthenticatedSession(session: Session | null): Promise<void> {
  if (!session?.access_token || !session.refresh_token) {
    clearSessionFallback();
    return;
  }

  if (isTauriRuntime()) {
    try {
      await saveRefreshTokenToKeychain(session.refresh_token);
    } catch (error) {
      console.error("[Auth] Failed to persist desktop refresh token in keychain:", error);
    }
  } else if (isInIframe()) {
    persistSessionFallback(session);
  } else {
    clearSessionFallback();
  }

  await saveOfflineIdentityFromSession(session);
}

export async function refreshCurrentSession(): Promise<Session | null> {
  if (!refreshInFlight) {
    refreshInFlight = refreshCurrentSessionUncached().finally(() => {
      refreshInFlight = null;
    });
  }

  return refreshInFlight;
}

export async function clearPersistentSession(): Promise<void> {
  clearSessionFallback();
  await clearRefreshTokenFromKeychain();
  await clearOfflineIdentity();
}

export async function hydrateFromBffCookie(): Promise<Session | null> {
  const apiUrl = getFunctionsUrl();
  const publishableKey = runtimeConfig.supabasePublishableKey;

  if (!apiUrl || !publishableKey) {
    return null;
  }

  try {
    const response = await fetch(`${apiUrl}/auth-session`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${publishableKey}`,
      },
      credentials: "include",
    });

    if (!response.ok) {
      return null;
    }

    const payload = await response.json().catch(() => null) as { session?: SessionTokens } | null;
    if (!payload?.session?.access_token || !payload.session.refresh_token) {
      return null;
    }

    return applyAuthenticatedSession(payload.session);
  } catch {
    return null;
  }
}

export function persistSessionFallback(session: Session | null): void {
  if (typeof window === "undefined") {
    return;
  }

  if (!session?.access_token || !session.refresh_token) {
    clearSessionFallback();
    return;
  }

  window.sessionStorage.setItem(SESSION_FALLBACK_STORAGE_KEY, JSON.stringify({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
  }));
}

export function clearSessionFallback(): void {
  if (typeof window === "undefined") {
    return;
  }

  window.sessionStorage.removeItem(SESSION_FALLBACK_STORAGE_KEY);
}

export function readSessionFallback(): SessionTokens | null {
  if (typeof window === "undefined") {
    return null;
  }

  const raw = window.sessionStorage.getItem(SESSION_FALLBACK_STORAGE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as Partial<SessionTokens>;
    if (!parsed.access_token || !parsed.refresh_token) {
      clearSessionFallback();
      return null;
    }

    return {
      access_token: parsed.access_token,
      refresh_token: parsed.refresh_token,
    };
  } catch {
    clearSessionFallback();
    return null;
  }
}

export async function saveOfflineIdentity(identity: OfflineIdentity): Promise<void> {
  await withOfflineIdentityStorage(
    async (store) => {
      store.put(identity, OFFLINE_IDENTITY_RECORD_KEY);
    },
    () => {
      localStorage.setItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY, JSON.stringify(identity));
    },
  );
}

export async function readOfflineIdentity(): Promise<OfflineIdentity | null> {
  return withOfflineIdentityStorage(
    async (store) => {
      const request = store.get(OFFLINE_IDENTITY_RECORD_KEY);
      return await idbRequest<OfflineIdentity | undefined>(request) ?? null;
    },
    () => {
      const raw = localStorage.getItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY);
      if (!raw) {
        return null;
      }

      try {
        const parsed = JSON.parse(raw) as Partial<OfflineIdentity>;
        if (typeof parsed.userId !== "string" || !parsed.userId) {
          localStorage.removeItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY);
          return null;
        }

        return {
          userId: parsed.userId,
          email: typeof parsed.email === "string" ? parsed.email : null,
          updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : new Date(0).toISOString(),
        };
      } catch {
        localStorage.removeItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY);
        return null;
      }
    },
  );
}

export async function clearOfflineIdentity(): Promise<void> {
  await withOfflineIdentityStorage(
    async (store) => {
      store.delete(OFFLINE_IDENTITY_RECORD_KEY);
    },
    () => {
      localStorage.removeItem(AUTH_OFFLINE_IDENTITY_STORAGE_KEY);
    },
  );
}

async function refreshCurrentSessionUncached(): Promise<Session | null> {
  if (isTauriRuntime()) {
    return refreshFromTauriKeychain();
  }

  if (!isInIframe()) {
    const bffSession = await hydrateFromBffCookie();
    if (bffSession) {
      return bffSession;
    }
  }

  const currentSession = await getMemorySession();
  const fallbackSession = readSessionFallback();
  const refreshToken = currentSession?.refresh_token || fallbackSession?.refresh_token;
  if (!refreshToken) {
    return null;
  }

  const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data.session) {
    return null;
  }

  await persistAuthenticatedSession(data.session);
  return data.session;
}

async function refreshFromTauriKeychain(): Promise<Session | null> {
  const refreshToken = await loadRefreshTokenFromKeychain();
  if (!refreshToken) {
    return null;
  }

  // Prevent race condition: if a new session was set in memory while we were loading from keychain,
  // do not attempt to refresh the old token (which would fail and emit SIGNED_OUT).
  const currentMemSession = await getMemorySession();
  if (currentMemSession?.access_token) {
    return currentMemSession;
  }

  const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data.session) {
    // Check if memory session was updated concurrently by a deep link before we clear anything
    const concurrentSession = await getMemorySession();
    if (concurrentSession?.access_token) {
      return concurrentSession;
    }
    await clearRefreshTokenFromKeychain();
    return null;
  }

  await persistAuthenticatedSession(data.session);
  return data.session;
}

async function restoreSessionFromFallback(): Promise<Session | null> {
  const fallbackSession = readSessionFallback();
  if (!fallbackSession) {
    return null;
  }

  try {
    return await applyAuthenticatedSession(fallbackSession);
  } catch {
    clearSessionFallback();
    return null;
  }
}

async function getMemorySession(): Promise<Session | null> {
  const { data, error } = await supabase.auth.getSession();
  if (error) {
    return null;
  }

  return data.session ?? null;
}

async function offlineOrUnauthenticatedState(): Promise<HydratedAuthState> {
  const offlineIdentity = await readOfflineIdentity();
  if (!offlineIdentity) {
    return {
      mode: "unauthenticated",
      session: null,
      user: null,
      offlineIdentity: null,
    };
  }

  return {
    mode: "offline",
    session: null,
    user: createOfflineUser(offlineIdentity),
    offlineIdentity,
  };
}

function onlineState(session: Session): HydratedAuthState {
  return {
    mode: "online",
    session,
    user: session.user,
    offlineIdentity: null,
  };
}

async function saveOfflineIdentityFromSession(session: Session): Promise<void> {
  if (!session.user?.id) {
    return;
  }

  await saveOfflineIdentity({
    userId: session.user.id,
    email: session.user.email ?? null,
    updatedAt: new Date().toISOString(),
  });
}

function createOfflineUser(identity: OfflineIdentity): User {
  return {
    id: identity.userId,
    email: identity.email ?? undefined,
    app_metadata: {},
    user_metadata: { offline: true },
    aud: "authenticated",
    created_at: identity.updatedAt,
  } as User;
}

async function saveRefreshTokenToKeychain(refreshToken: string): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return;
  }

  await invoke<void>("save_refresh_token", { refreshToken });
}

async function loadRefreshTokenFromKeychain(): Promise<string | null> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return null;
  }

  try {
    return await invoke<string | null>("load_refresh_token");
  } catch {
    return null;
  }
}

async function clearRefreshTokenFromKeychain(): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return;
  }

  await invoke<void>("clear_refresh_token");
}

async function withOfflineIdentityStorage<T>(
  indexedDbAction: (store: IDBObjectStore) => Promise<T> | T,
  fallbackAction: () => T,
): Promise<T> {
  if (typeof window === "undefined") {
    return fallbackAction();
  }

  try {
    const db = await openAuthStateDb();
    try {
      const tx = db.transaction(OFFLINE_IDENTITY_STORE, "readwrite");
      const result = await indexedDbAction(tx.objectStore(OFFLINE_IDENTITY_STORE));
      await finishTransaction(tx);
      return result;
    } finally {
      db.close();
    }
  } catch {
    return fallbackAction();
  }
}

function openAuthStateDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const indexedDb = window.indexedDB;
    if (!indexedDb) {
      reject(new Error("IndexedDB unavailable"));
      return;
    }

    const request = indexedDb.open(AUTH_STATE_DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      const hasStore = db.objectStoreNames?.contains?.(OFFLINE_IDENTITY_STORE) ?? false;
      if (!hasStore) {
        db.createObjectStore(OFFLINE_IDENTITY_STORE);
      }
    };
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onsuccess = () => resolve(request.result);
  });
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
    request.onsuccess = () => resolve(request.result);
  });
}

function finishTransaction(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));

    if (!("oncomplete" in tx)) {
      resolve();
    }

    setTimeout(resolve, 0);
  });
}

function getFunctionsUrl(): string | null {
  return runtimeConfig.supabaseFunctionsUrl;
}
