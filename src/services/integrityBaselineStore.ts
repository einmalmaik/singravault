interface IntegrityBaselineEnvelope {
  userId: string;
  payload: string;
  updatedAt: string;
}

const DB_NAME = 'singra-vault-integrity';
const DB_VERSION = 1;
const BASELINES_STORE = 'baselines';

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
    const request = ensureIndexedDb().open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(BASELINES_STORE)) {
        db.createObjectStore(BASELINES_STORE, { keyPath: 'userId' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  return dbPromise;
}

function withStore<T>(
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
        const transaction = db.transaction(BASELINES_STORE, mode);
        const store = transaction.objectStore(BASELINES_STORE);
        handler(store, resolve, reject);
      })
      .catch(reject);
  });
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
