// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Local persistence for the operation-log device signing private key.
 *
 * The stored value is a non-extractable WebCrypto CryptoKey handle. This
 * module never exports raw key material, JWK, SPKI private bytes or secrets.
 * If the platform cannot persist non-extractable keys, callers must fail
 * closed and keep migration/write actions blocked.
 */

const DB_NAME = 'singra-vault-oplog-device-signing-keys';
const DB_VERSION = 1;
const STORE_NAME = 'deviceSigningKeys';

export interface VaultOpLogDeviceSigningKeyRef {
  readonly userId: string;
  readonly vaultId: string;
  readonly deviceId: string;
}

export interface StoredVaultOpLogDeviceSigningKeyRef extends VaultOpLogDeviceSigningKeyRef {
  readonly updatedAt: string;
}

export class VaultOpLogDeviceSigningKeyStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultOpLogDeviceSigningKeyStoreError';
  }
}

export async function saveVaultOpLogDeviceSigningKey(
  ref: VaultOpLogDeviceSigningKeyRef & { readonly privateKey: CryptoKey },
): Promise<void> {
  assertNonExtractableSigningKey(ref.privateKey);
  const db = await openDb();
  try {
    await idbRequest(
      transactionStore(db, 'readwrite').put({
        id: storageId(ref),
        userId: ref.userId,
        vaultId: ref.vaultId,
        deviceId: ref.deviceId,
        privateKey: ref.privateKey,
        updatedAt: new Date().toISOString(),
      }),
    );
  } catch (error) {
    throw new VaultOpLogDeviceSigningKeyStoreError(
      error instanceof Error ? error.message : 'failed to persist device signing key',
    );
  } finally {
    db.close();
  }
}

export async function loadVaultOpLogDeviceSigningKey(
  ref: VaultOpLogDeviceSigningKeyRef,
): Promise<CryptoKey | null> {
  const db = await openDb();
  try {
    const row = await idbRequest<unknown>(
      transactionStore(db, 'readonly').get(storageId(ref)),
    );
    if (!isStoredSigningKey(row)) {
      return null;
    }
    assertNonExtractableSigningKey(row.privateKey);
    return row.privateKey;
  } finally {
    db.close();
  }
}

export async function listVaultOpLogDeviceSigningKeyRefs(
  input: Pick<VaultOpLogDeviceSigningKeyRef, 'userId' | 'vaultId'>,
): Promise<StoredVaultOpLogDeviceSigningKeyRef[]> {
  const db = await openDb();
  try {
    const rows = await idbRequest<unknown[]>(
      transactionStore(db, 'readonly').getAll(),
    );
    return rows
      .filter(isStoredSigningKeyRow)
      .filter((row) => row.userId === input.userId && row.vaultId === input.vaultId)
      .map((row) => ({
        userId: row.userId,
        vaultId: row.vaultId,
        deviceId: row.deviceId,
        updatedAt: row.updatedAt,
      }))
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  } finally {
    db.close();
  }
}

function assertNonExtractableSigningKey(key: CryptoKey): void {
  if (key.type !== 'private' || key.extractable !== false || !key.usages.includes('sign')) {
    throw new VaultOpLogDeviceSigningKeyStoreError('device signing key must be a non-extractable private signing key');
  }
}

function storageId(ref: VaultOpLogDeviceSigningKeyRef): string {
  return `${ref.userId}:${ref.vaultId}:${ref.deviceId}`;
}

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new VaultOpLogDeviceSigningKeyStoreError('IndexedDB is not available'));
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('failed to open device signing key store'));
  });
}

function transactionStore(db: IDBDatabase, mode: IDBTransactionMode): IDBObjectStore {
  return db.transaction(STORE_NAME, mode).objectStore(STORE_NAME);
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function isStoredSigningKey(value: unknown): value is { readonly privateKey: CryptoKey } {
  return typeof value === 'object'
    && value !== null
    && 'privateKey' in value
    && (value as { privateKey?: unknown }).privateKey instanceof CryptoKey;
}

function isStoredSigningKeyRow(value: unknown): value is {
  readonly userId: string;
  readonly vaultId: string;
  readonly deviceId: string;
  readonly privateKey: CryptoKey;
  readonly updatedAt: string;
} {
  if (!isStoredSigningKey(value)) {
    return false;
  }
  const row = value as Record<string, unknown>;
  return typeof row.userId === 'string'
    && typeof row.vaultId === 'string'
    && typeof row.deviceId === 'string'
    && typeof row.updatedAt === 'string';
}
