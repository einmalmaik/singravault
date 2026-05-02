interface IntegrityBaselineEnvelope {
  userId: string;
  payload: string;
  updatedAt: string;
}

export const INTEGRITY_DB_NAME = 'singra-vault-integrity';
export const INTEGRITY_DB_VERSION = 3;
export const INTEGRITY_BASELINES_STORE = 'baselines';
export const MANIFEST_HIGH_WATER_MARKS_STORE = 'manifest-high-water-marks';
export const MANIFEST_PERSIST_RETRY_STORE = 'manifest-persist-retry';
export const MANIFEST_ENVELOPES_STORE = 'manifest-envelopes';

let dbPromise: Promise<IDBDatabase> | null = null;

function ensureIndexedDb(): IDBFactory {
  if (typeof indexedDB === 'undefined') {
    throw new Error('IndexedDB is not available for integrity baseline storage.');
  }

  return indexedDB;
}

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = new Promise((resolve, reject) => {
    const request = ensureIndexedDb().open(INTEGRITY_DB_NAME, INTEGRITY_DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(INTEGRITY_BASELINES_STORE)) {
        db.createObjectStore(INTEGRITY_BASELINES_STORE, { keyPath: 'userId' });
      }
      if (!db.objectStoreNames.contains(MANIFEST_HIGH_WATER_MARKS_STORE)) {
        db.createObjectStore(MANIFEST_HIGH_WATER_MARKS_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(MANIFEST_PERSIST_RETRY_STORE)) {
        db.createObjectStore(MANIFEST_PERSIST_RETRY_STORE, { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains(MANIFEST_ENVELOPES_STORE)) {
        db.createObjectStore(MANIFEST_ENVELOPES_STORE, { keyPath: 'key' });
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
        dbPromise = null;
      };
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });

  return dbPromise;
}

export function withIntegrityObjectStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  handler: (
    store: IDBObjectStore,
    resolve: (value: T) => void,
    reject: (reason?: unknown) => void,
  ) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    openDb()
      .then((db) => {
        const transaction = db.transaction(storeName, mode);
        const store = transaction.objectStore(storeName);
        handler(store, resolve, reject);
      })
      .catch(reject);
  });
}

function withStore<T>(
  mode: IDBTransactionMode,
  handler: (
    store: IDBObjectStore,
    resolve: (value: T) => void,
    reject: (reason?: unknown) => void,
  ) => void,
): Promise<T> {
  return withIntegrityObjectStore(INTEGRITY_BASELINES_STORE, mode, handler);
}

export async function loadIntegrityBaselineEnvelope(userId: string): Promise<string | null> {
  return withStore<string | null>('readonly', (store, resolve, reject) => {
    const request = store.get(userId);
    request.onsuccess = () => {
      const record = request.result as IntegrityBaselineEnvelope | undefined;
      resolve(record?.payload ?? null);
    };
    request.onerror = () => reject(request.error);
  });
}

export async function saveIntegrityBaselineEnvelope(userId: string, payload: string): Promise<void> {
  await withStore<void>('readwrite', (store, resolve, reject) => {
    const request = store.put({
      userId,
      payload,
      updatedAt: new Date().toISOString(),
    } satisfies IntegrityBaselineEnvelope);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

export async function removeIntegrityBaselineEnvelope(userId: string): Promise<void> {
  await withStore<void>('readwrite', (store, resolve, reject) => {
    const request = store.delete(userId);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}
