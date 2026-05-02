import {
  MANIFEST_PERSIST_RETRY_STORE,
  withIntegrityObjectStore,
} from '@/services/integrityBaselineStore';

export interface ManifestPersistRetryRecordV1 {
  schemaVersion: 1;
  key: string;
  userId: string;
  vaultId: string;
  attemptedAt: string;
  snapshotDigest: string;
  lastErrorCode: string;
}

export class ManifestPersistRetryStoreError extends Error {
  readonly code = 'store_unavailable';

  constructor() {
    super('Manifest persist retry store is unavailable.');
    this.name = 'ManifestPersistRetryStoreError';
  }
}

export function buildManifestPersistRetryKey(userId: string, vaultId: string): string {
  return `${userId}::${vaultId}`;
}

export async function loadManifestPersistRetryRecord(
  userId: string,
  vaultId: string,
): Promise<ManifestPersistRetryRecordV1 | null> {
  try {
    return await withIntegrityObjectStore<ManifestPersistRetryRecordV1 | null>(
      MANIFEST_PERSIST_RETRY_STORE,
      'readonly',
      (store, resolve, reject) => {
        const request = store.get(buildManifestPersistRetryKey(userId, vaultId));
        request.onsuccess = () => {
          const record = request.result as ManifestPersistRetryRecordV1 | undefined;
          if (record !== undefined && !isManifestPersistRetryRecord(record)) {
            reject(new ManifestPersistRetryStoreError());
            return;
          }
          resolve(record ?? null);
        };
        request.onerror = () => reject(request.error);
      },
    );
  } catch {
    throw new ManifestPersistRetryStoreError();
  }
}

export async function saveManifestPersistRetryRecord(input: {
  userId: string;
  vaultId: string;
  snapshotDigest: string;
  lastErrorCode: string;
}): Promise<void> {
  try {
    await withIntegrityObjectStore<void>(
      MANIFEST_PERSIST_RETRY_STORE,
      'readwrite',
      (store, resolve, reject) => {
        const key = buildManifestPersistRetryKey(input.userId, input.vaultId);
        const request = store.put({
          schemaVersion: 1,
          key,
          userId: input.userId,
          vaultId: input.vaultId,
          attemptedAt: new Date().toISOString(),
          snapshotDigest: input.snapshotDigest,
          lastErrorCode: sanitizeErrorCode(input.lastErrorCode),
        } satisfies ManifestPersistRetryRecordV1);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      },
    );
  } catch {
    throw new ManifestPersistRetryStoreError();
  }
}

export async function removeManifestPersistRetryRecord(
  userId: string,
  vaultId: string,
): Promise<void> {
  try {
    await withIntegrityObjectStore<void>(
      MANIFEST_PERSIST_RETRY_STORE,
      'readwrite',
      (store, resolve, reject) => {
        const request = store.delete(buildManifestPersistRetryKey(userId, vaultId));
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      },
    );
  } catch {
    throw new ManifestPersistRetryStoreError();
  }
}

function isManifestPersistRetryRecord(
  value: ManifestPersistRetryRecordV1 | undefined,
): value is ManifestPersistRetryRecordV1 {
  return value?.schemaVersion === 1
    && typeof value.key === 'string'
    && typeof value.userId === 'string'
    && typeof value.vaultId === 'string'
    && typeof value.attemptedAt === 'string'
    && typeof value.snapshotDigest === 'string'
    && typeof value.lastErrorCode === 'string';
}

function sanitizeErrorCode(code: string): string {
  const sanitized = code.toLowerCase().replace(/[^a-z0-9_:-]/g, '_').slice(0, 80);
  return sanitized || 'manifest_persist_failed';
}
