import {
  MANIFEST_HIGH_WATER_MARKS_STORE,
  withIntegrityObjectStore,
} from '@/services/integrityBaselineStore';

export interface ManifestHighWaterMarkRecordV1 {
  schemaVersion: 1;
  key: string;
  userId: string;
  vaultId: string;
  manifestRevision: number;
  manifestHash: string;
  keyId: string;
  firstSeenAt: string;
  updatedAt: string;
}

export type ManifestHighWaterMarkErrorCode =
  | 'store_unavailable'
  | 'revision_rollback'
  | 'same_revision_hash_mismatch'
  | 'key_id_mismatch';

export class ManifestHighWaterMarkError extends Error {
  readonly code: ManifestHighWaterMarkErrorCode;

  constructor(code: ManifestHighWaterMarkErrorCode) {
    super(`Manifest high-water mark error: ${code}`);
    this.name = 'ManifestHighWaterMarkError';
    this.code = code;
  }
}

export function buildManifestHighWaterMarkKey(userId: string, vaultId: string): string {
  return `${userId}::${vaultId}`;
}

export async function loadManifestHighWaterMark(
  userId: string,
  vaultId: string,
): Promise<ManifestHighWaterMarkRecordV1 | null> {
  try {
    return await withIntegrityObjectStore<ManifestHighWaterMarkRecordV1 | null>(
      MANIFEST_HIGH_WATER_MARKS_STORE,
      'readonly',
      (store, resolve, reject) => {
        const request = store.get(buildManifestHighWaterMarkKey(userId, vaultId));
        request.onsuccess = () => {
          const record = request.result as ManifestHighWaterMarkRecordV1 | undefined;
          if (record !== undefined && !isManifestHighWaterMarkRecord(record)) {
            reject(new ManifestHighWaterMarkError('store_unavailable'));
            return;
          }
          resolve(record ?? null);
        };
        request.onerror = () => reject(request.error);
      },
    );
  } catch {
    throw new ManifestHighWaterMarkError('store_unavailable');
  }
}

export async function saveManifestHighWaterMark(input: {
  userId: string;
  vaultId: string;
  manifestRevision: number;
  manifestHash: string;
  keyId: string;
}): Promise<ManifestHighWaterMarkRecordV1> {
  try {
    return await withIntegrityObjectStore<ManifestHighWaterMarkRecordV1>(
      MANIFEST_HIGH_WATER_MARKS_STORE,
      'readwrite',
      (store, resolve, reject) => {
        const key = buildManifestHighWaterMarkKey(input.userId, input.vaultId);
        const getRequest = store.get(key);
        getRequest.onerror = () => reject(getRequest.error);
        getRequest.onsuccess = () => {
          const existing = getRequest.result as ManifestHighWaterMarkRecordV1 | undefined;
          let nextRecord: ManifestHighWaterMarkRecordV1;

          try {
            nextRecord = buildNextManifestHighWaterMark(existing, input, key);
          } catch (error) {
            reject(error);
            return;
          }

          const putRequest = store.put(nextRecord);
          putRequest.onsuccess = () => resolve(nextRecord);
          putRequest.onerror = () => reject(putRequest.error);
        };
      },
    );
  } catch (error) {
    if (error instanceof ManifestHighWaterMarkError) {
      throw error;
    }
    throw new ManifestHighWaterMarkError('store_unavailable');
  }
}

export async function removeManifestHighWaterMark(userId: string, vaultId: string): Promise<void> {
  try {
    await withIntegrityObjectStore<void>(
      MANIFEST_HIGH_WATER_MARKS_STORE,
      'readwrite',
      (store, resolve, reject) => {
        const request = store.delete(buildManifestHighWaterMarkKey(userId, vaultId));
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      },
    );
  } catch {
    throw new ManifestHighWaterMarkError('store_unavailable');
  }
}

function buildNextManifestHighWaterMark(
  existing: ManifestHighWaterMarkRecordV1 | undefined,
  input: {
    userId: string;
    vaultId: string;
    manifestRevision: number;
    manifestHash: string;
    keyId: string;
  },
  key: string,
): ManifestHighWaterMarkRecordV1 {
  const now = new Date().toISOString();
  if (existing !== undefined && !isManifestHighWaterMarkRecord(existing)) {
    throw new ManifestHighWaterMarkError('store_unavailable');
  }

  if (!existing) {
    return {
      schemaVersion: 1,
      key,
      userId: input.userId,
      vaultId: input.vaultId,
      manifestRevision: input.manifestRevision,
      manifestHash: input.manifestHash,
      keyId: input.keyId,
      firstSeenAt: now,
      updatedAt: now,
    };
  }

  if (existing.keyId !== input.keyId) {
    throw new ManifestHighWaterMarkError('key_id_mismatch');
  }

  if (input.manifestRevision < existing.manifestRevision) {
    throw new ManifestHighWaterMarkError('revision_rollback');
  }

  if (
    input.manifestRevision === existing.manifestRevision
    && input.manifestHash !== existing.manifestHash
  ) {
    throw new ManifestHighWaterMarkError('same_revision_hash_mismatch');
  }

  return {
    ...existing,
    manifestRevision: input.manifestRevision,
    manifestHash: input.manifestHash,
    updatedAt: now,
  };
}

function isManifestHighWaterMarkRecord(
  value: ManifestHighWaterMarkRecordV1 | undefined,
): value is ManifestHighWaterMarkRecordV1 {
  return value?.schemaVersion === 1
    && typeof value.key === 'string'
    && typeof value.userId === 'string'
    && typeof value.vaultId === 'string'
    && Number.isSafeInteger(value.manifestRevision)
    && typeof value.manifestHash === 'string'
    && typeof value.keyId === 'string'
    && typeof value.firstSeenAt === 'string'
    && typeof value.updatedAt === 'string';
}
