import { isTauriRuntime } from "./runtime";
import { getTauriInvoke } from "./tauriInvoke";

const DB_NAME = "singra-local-secrets";
const DB_VERSION = 1;
const META_STORE = "meta";
const SECRETS_STORE = "secrets";
const WRAPPING_KEY_ID = "browser-wrapping-key";
const WRAPPING_KEY_ALGORITHM = { name: "AES-GCM", length: 256 } as const;
const WRAPPING_IV_LENGTH = 12;

export class LocalSecretStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalSecretStoreError";
  }
}

export class LocalSecretStoreUnsupportedError extends LocalSecretStoreError {
  constructor(message = "Secure local secret storage is not available in this runtime.") {
    super(message);
    this.name = "LocalSecretStoreUnsupportedError";
  }
}

interface SecretRecord {
  key: string;
  payload: string;
  updatedAt: string;
}

let dbPromise: Promise<IDBDatabase> | null = null;
let browserWrappingKeyCache: CryptoKey | null = null;
const browserSecretPayloadCache = new Map<string, string>();

export async function isLocalSecretStoreSupported(): Promise<boolean> {
  if (isTauriRuntime()) {
    return (await getTauriInvoke()) !== null;
  }

  if (!isBrowserSecretStoreAvailable()) {
    return false;
  }

  try {
    return (await getBrowserWrappingKey(true)) !== null;
  } catch {
    return false;
  }
}

export async function saveLocalSecretString(key: string, value: string): Promise<void> {
  await saveLocalSecretBytes(key, new TextEncoder().encode(value));
}

export async function loadLocalSecretString(key: string): Promise<string | null> {
  const bytes = await loadLocalSecretBytes(key);
  if (!bytes) {
    return null;
  }

  return new TextDecoder().decode(bytes);
}

export async function saveLocalSecretBytes(key: string, value: Uint8Array): Promise<void> {
  if (isTauriRuntime()) {
    await saveTauriSecret(key, bytesToBase64(value));
    return;
  }

  if (!isBrowserSecretStoreAvailable()) {
    throw new LocalSecretStoreUnsupportedError();
  }

  const wrappingKey = await getBrowserWrappingKey(true);
  if (!wrappingKey) {
    throw new LocalSecretStoreUnsupportedError();
  }

  const iv = crypto.getRandomValues(new Uint8Array(WRAPPING_IV_LENGTH));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    value,
  );

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  const encodedPayload = bytesToBase64(combined);

  browserSecretPayloadCache.set(key, encodedPayload);

  await withStore<void>(SECRETS_STORE, "readwrite", (store, _transaction, resolve, reject) => {
    const request = store.put({
      key,
      payload: encodedPayload,
      updatedAt: new Date().toISOString(),
    } satisfies SecretRecord);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function loadLocalSecretBytes(key: string): Promise<Uint8Array | null> {
  if (isTauriRuntime()) {
    const encoded = await loadTauriSecret(key);
    return encoded ? base64ToBytes(encoded) : null;
  }

  if (!isBrowserSecretStoreAvailable()) {
    return null;
  }

  const wrappingKey = await getBrowserWrappingKey(false);
  if (!wrappingKey) {
    return null;
  }

  const record = await withStore<SecretRecord | null>(SECRETS_STORE, "readonly", (store, _transaction, resolve, reject) => {
    const request = store.get(key);
    request.onsuccess = () => resolve((request.result as SecretRecord | undefined) ?? null);
    request.onerror = () => reject(request.error);
  });

  const payload = record?.payload ?? browserSecretPayloadCache.get(key) ?? null;
  if (!payload) {
    return null;
  }

  const combined = base64ToBytes(payload);
  if (combined.length <= WRAPPING_IV_LENGTH) {
    browserSecretPayloadCache.delete(key);
    await removeLocalSecret(key);
    return null;
  }

  const iv = combined.slice(0, WRAPPING_IV_LENGTH);
  const ciphertext = combined.slice(WRAPPING_IV_LENGTH);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      wrappingKey,
      ciphertext,
    );

    return new Uint8Array(decrypted);
  } catch {
    browserSecretPayloadCache.delete(key);
    await removeLocalSecret(key);
    return null;
  }
}

export async function removeLocalSecret(key: string): Promise<void> {
  if (isTauriRuntime()) {
    await clearTauriSecret(key);
    return;
  }

  if (!isBrowserSecretStoreAvailable()) {
    return;
  }

  browserSecretPayloadCache.delete(key);

  await withStore<void>(SECRETS_STORE, "readwrite", (store, _transaction, resolve, reject) => {
    const request = store.delete(key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

function isBrowserSecretStoreAvailable(): boolean {
  if (typeof window === "undefined") {
    return false;
  }

  return typeof window.indexedDB !== "undefined"
    && typeof window.crypto !== "undefined"
    && typeof window.crypto.subtle !== "undefined";
}

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: "key" });
      }
      if (!db.objectStoreNames.contains(SECRETS_STORE)) {
        db.createObjectStore(SECRETS_STORE, { keyPath: "key" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  return dbPromise;
}

function withStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  handler: (
    store: IDBObjectStore,
    transaction: IDBTransaction,
    resolve: (value: T) => void,
    reject: (reason?: unknown) => void,
  ) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    openDb()
      .then((db) => {
        const transaction = db.transaction(storeName, mode);
        const store = transaction.objectStore(storeName);
        handler(store, transaction, resolve, reject);
      })
      .catch(reject);
  });
}

async function getBrowserWrappingKey(createIfMissing: boolean): Promise<CryptoKey | null> {
  if (browserWrappingKeyCache) {
    return browserWrappingKeyCache;
  }

  const existing = await withStore<CryptoKey | null>(META_STORE, "readonly", (store, _transaction, resolve, reject) => {
    const request = store.get(WRAPPING_KEY_ID);
    request.onsuccess = () => {
      const record = request.result as { key: string; wrappingKey?: CryptoKey } | undefined;
      resolve(record?.wrappingKey ?? null);
    };
    request.onerror = () => reject(request.error);
  });

  if (existing) {
    browserWrappingKeyCache = existing;
    return existing;
  }

  if (!createIfMissing) {
    return null;
  }

  const wrappingKey = await crypto.subtle.generateKey(
    WRAPPING_KEY_ALGORITHM,
    false,
    ["encrypt", "decrypt"],
  );

  browserWrappingKeyCache = wrappingKey;
  void withStore<void>(META_STORE, "readwrite", (store, _transaction, resolve, reject) => {
    const request = store.put({
      key: WRAPPING_KEY_ID,
      wrappingKey,
    });

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  }).catch(() => {
    // Some runtimes and test adapters cannot persist non-extractable CryptoKeys.
    // The in-memory cache still secures the current session without silently
    // downgrading the stored payload format.
  });

  return wrappingKey;
}

async function saveTauriSecret(key: string, value: string): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    throw new LocalSecretStoreUnsupportedError();
  }

  await invoke("save_local_secret", { key, value });
}

async function loadTauriSecret(key: string): Promise<string | null> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return null;
  }

  return invoke<string | null>("load_local_secret", { key });
}

async function clearTauriSecret(key: string): Promise<void> {
  const invoke = await getTauriInvoke();
  if (!invoke) {
    return;
  }

  await invoke("clear_local_secret", { key });
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}
