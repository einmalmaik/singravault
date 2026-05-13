// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Local cache for the last fully verified Vault OpLog view.
 *
 * SECURITY: This cache is an offline availability aid, not a trust root. It
 * stores only operation rows, sealed record rows and public device-trust
 * metadata that were already verified online. It never stores plaintext,
 * Vault keys, Device Keys, private signing keys, recovery codes or auth tokens.
 */

import type { TrustedDeviceRecordV1 } from './types';
import type { VaultOperationRow, VaultRecordRow } from './vaultOpLogRpcTypes';

export const VAULT_OPLOG_OFFLINE_CACHE_SCHEMA = 'vault-oplog-offline-cache-v1' as const;

const DB_NAME = 'singra-vault-oplog-offline';
const DB_VERSION = 1;
const STORE_NAME = 'verified-vaults';

export interface VaultOpLogOfflineCacheEntry {
  readonly schema: typeof VAULT_OPLOG_OFFLINE_CACHE_SCHEMA;
  readonly cacheKey: string;
  readonly userId: string;
  readonly vaultId: string;
  readonly currentHead: string | null;
  readonly currentSequenceNumber: number;
  readonly verifiedAt: string;
  readonly operations: readonly VaultOperationRow[];
  readonly records: readonly VaultRecordRow[];
  readonly trustedDevices: readonly TrustedDeviceRecordV1[];
}

function cacheKey(userId: string, vaultId: string): string {
  return `${userId}:${vaultId}`;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB is not available'));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'cacheKey' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
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
  return new Promise((resolve, reject) => {
    openDb()
      .then((db) => {
        const tx = db.transaction(STORE_NAME, mode);
        const store = tx.objectStore(STORE_NAME);
        const closeAndResolve = (value: T) => {
          db.close?.();
          resolve(value);
        };
        const closeAndReject = (reason?: unknown) => {
          db.close?.();
          reject(reason);
        };
        tx.onerror = () => closeAndReject(tx.error ?? new Error('IndexedDB transaction failed'));
        tx.onabort = () => closeAndReject(tx.error ?? new Error('IndexedDB transaction aborted'));
        handler(store, closeAndResolve, closeAndReject);
      })
      .catch(reject);
  });
}

export async function saveVerifiedVaultOpLogOfflineCache(input: {
  readonly userId: string;
  readonly vaultId: string;
  readonly currentHead: string | null;
  readonly currentSequenceNumber: number;
  readonly operations: readonly VaultOperationRow[];
  readonly records: readonly VaultRecordRow[];
  readonly trustedDevices: readonly TrustedDeviceRecordV1[];
}): Promise<void> {
  const entry: VaultOpLogOfflineCacheEntry = {
    schema: VAULT_OPLOG_OFFLINE_CACHE_SCHEMA,
    cacheKey: cacheKey(input.userId, input.vaultId),
    userId: input.userId,
    vaultId: input.vaultId,
    currentHead: input.currentHead,
    currentSequenceNumber: input.currentSequenceNumber,
    verifiedAt: new Date().toISOString(),
    operations: input.operations.map((operation) => ({ ...operation })),
    records: input.records.map((record) => ({ ...record })),
    trustedDevices: input.trustedDevices.map((device) => ({ ...device })),
  };

  assertCacheEntryShape(entry, input.userId, input.vaultId);

  await withStore<void>('readwrite', (store, resolve, reject) => {
    const req = store.put(entry);
    req.onsuccess = () => setTimeout(resolve, 0);
    req.onerror = () => reject(req.error);
  });
}

export async function loadVerifiedVaultOpLogOfflineCache(input: {
  readonly userId: string;
  readonly vaultId: string;
}): Promise<VaultOpLogOfflineCacheEntry | null> {
  return withStore<VaultOpLogOfflineCacheEntry | null>('readonly', (store, resolve, reject) => {
    const req = store.get(cacheKey(input.userId, input.vaultId));
    req.onsuccess = () => {
      const entry = req.result as VaultOpLogOfflineCacheEntry | undefined;
      if (!entry) {
        resolve(null);
        return;
      }
      try {
        assertCacheEntryShape(entry, input.userId, input.vaultId);
        resolve(entry);
      } catch {
        resolve(null);
      }
    };
    req.onerror = () => reject(req.error);
  });
}

export async function listVerifiedVaultOpLogOfflineCachesForUser(input: {
  readonly userId: string;
}): Promise<readonly VaultOpLogOfflineCacheEntry[]> {
  return withStore<readonly VaultOpLogOfflineCacheEntry[]>('readonly', (store, resolve, reject) => {
    const req = store.getAll();
    req.onsuccess = () => {
      const rows = Array.isArray(req.result) ? req.result : [];
      const entries = rows.flatMap((row): VaultOpLogOfflineCacheEntry[] => {
        const entry = row as VaultOpLogOfflineCacheEntry;
        if (entry?.userId !== input.userId || typeof entry.vaultId !== 'string') {
          return [];
        }
        try {
          assertCacheEntryShape(entry, input.userId, entry.vaultId);
          return [entry];
        } catch {
          return [];
        }
      });

      resolve(entries.sort((left, right) => right.verifiedAt.localeCompare(left.verifiedAt)));
    };
    req.onerror = () => reject(req.error);
  });
}

export async function removeVerifiedVaultOpLogOfflineCache(input: {
  readonly userId: string;
  readonly vaultId: string;
}): Promise<void> {
  await withStore<void>('readwrite', (store, resolve, reject) => {
    const req = store.delete(cacheKey(input.userId, input.vaultId));
    req.onsuccess = () => setTimeout(resolve, 0);
    req.onerror = () => reject(req.error);
  });
}

function assertCacheEntryShape(
  entry: VaultOpLogOfflineCacheEntry,
  userId: string,
  vaultId: string,
): void {
  if (
    entry.schema !== VAULT_OPLOG_OFFLINE_CACHE_SCHEMA
    || entry.cacheKey !== cacheKey(userId, vaultId)
    || entry.userId !== userId
    || entry.vaultId !== vaultId
    || (entry.currentHead !== null && typeof entry.currentHead !== 'string')
    || !Number.isSafeInteger(entry.currentSequenceNumber)
    || entry.currentSequenceNumber < 0
    || typeof entry.verifiedAt !== 'string'
    || !Array.isArray(entry.operations)
    || !Array.isArray(entry.records)
    || !Array.isArray(entry.trustedDevices)
  ) {
    throw new Error('invalid_oplog_offline_cache_entry');
  }

  for (const operation of entry.operations) {
    if (
      operation.vaultId !== vaultId
      || typeof operation.opId !== 'string'
      || typeof operation.opHash !== 'string'
      || typeof operation.signature !== 'string'
      || !Number.isSafeInteger(operation.sequenceNumber)
    ) {
      throw new Error('invalid_oplog_offline_operation');
    }
  }

  for (const record of entry.records) {
    if (
      record.vaultId !== vaultId
      || typeof record.recordId !== 'string'
      || typeof record.ciphertext !== 'string'
      || typeof record.ciphertextHash !== 'string'
      || typeof record.aadHash !== 'string'
    ) {
      throw new Error('invalid_oplog_offline_record');
    }
  }

  for (const device of entry.trustedDevices) {
    if (
      device.vaultId !== vaultId
      || typeof device.deviceId !== 'string'
      || typeof device.publicSigningKey !== 'string'
      || (device.status !== 'trusted' && device.status !== 'revoked')
      || !Number.isSafeInteger(device.trustEpoch)
    ) {
      throw new Error('invalid_oplog_offline_trust_record');
    }
  }
}
