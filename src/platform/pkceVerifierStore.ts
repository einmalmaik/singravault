// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { getTauriInvoke } from "./tauriInvoke";

type StorageValue = string | null;

const PKCE_VERIFIER_CREATED_AT_SUFFIX = "-created-at";
const PKCE_VERIFIER_MAX_AGE_MS = 10 * 60 * 1000;

export async function savePkceVerifier(key: string, verifier: string): Promise<void> {
  const normalizedKey = key.trim();
  const normalizedVerifier = verifier.trim();
  if (!normalizedKey || !normalizedVerifier) {
    return;
  }

  const createdAt = Date.now().toString();
  forEachPkceStorage((storage) => {
    storage.setItem(normalizedKey, normalizedVerifier);
    storage.setItem(getPkceVerifierCreatedAtKey(normalizedKey), createdAt);
  });
  await saveNativePkceVerifier(normalizedKey, normalizedVerifier);
}

export async function loadPkceVerifier(key: string): Promise<StorageValue> {
  const normalizedKey = key.trim();
  if (!normalizedKey) {
    return null;
  }

  const sessionValue = withWebStorage("sessionStorage", (storage) => storage.getItem(normalizedKey));
  if (sessionValue) {
    return sessionValue;
  }

  if (isPkceVerifierExpired(normalizedKey)) {
    await clearPkceVerifier(normalizedKey);
    return null;
  }

  const localValue = withWebStorage("localStorage", (storage) => storage.getItem(normalizedKey));
  if (localValue) {
    return localValue;
  }

  return loadNativePkceVerifier(normalizedKey);
}

export async function clearPkceVerifier(key: string): Promise<void> {
  const normalizedKey = key.trim();
  if (!normalizedKey) {
    return;
  }

  forEachPkceStorage((storage) => {
    storage.removeItem(normalizedKey);
    storage.removeItem(getPkceVerifierCreatedAtKey(normalizedKey));
  });
  await clearNativePkceVerifier(normalizedKey);
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
