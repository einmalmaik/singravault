// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Persistence adapters for the local pending operation queue.
 *
 * Provides a pluggable interface so the queue logic stays independent of the
 * underlying storage technology. The product default is IndexedDB. The
 * localStorage adapter remains only as a legacy migration source and for
 * narrow unit-test fixtures.
 */

import type { PendingLocalOperation, QueuePersistence } from './vaultOpLogPendingQueueTypes';

export const LEGACY_LOCAL_STORAGE_QUEUE_PREFIX = 'singra:vaultOpLog:pending:' as const;
const DB_NAME = 'singra-vault-oplog-pending-queue';
const DB_VERSION = 1;
const STORE_NAME = 'pendingOperations';

function legacyStorageKey(vaultId: string): string {
  return `${LEGACY_LOCAL_STORAGE_QUEUE_PREFIX}${vaultId}`;
}

interface StoredPendingLocalOperation extends PendingLocalOperation {
  readonly id: string;
  readonly vaultId: string;
}

export type LegacyQueueMigrationResult =
  | { readonly kind: 'not_needed' }
  | { readonly kind: 'migrated'; readonly count: number }
  | { readonly kind: 'blocked'; readonly reason: 'missing_storage' | 'malformed_legacy_queue' | 'indexeddb_unavailable' | 'verification_failed' };

/**
 * Product persistence backed by IndexedDB.
 *
 * SECURITY: This stores only signed operations and sealed record rows. The
 * legacy localStorage key is removed only after the new rows are written and
 * reloaded successfully.
 */
export class IndexedDbQueuePersistence implements QueuePersistence {
  async loadAll(vaultId: string): Promise<readonly PendingLocalOperation[]> {
    await this.migrateLegacyLocalStorageQueue(vaultId).catch(() => ({ kind: 'blocked', reason: 'verification_failed' }));
    const db = await openDb();
    try {
      const rows = await idbRequest<unknown[]>(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll());
      return rows
        .filter(isStoredPendingOperation)
        .filter((row) => row.vaultId === vaultId)
        .map(stripStorageFields)
        .sort((a, b) => a.createdAtLocal.localeCompare(b.createdAtLocal));
    } finally {
      db.close?.();
    }
  }

  async saveAll(vaultId: string, operations: readonly PendingLocalOperation[]): Promise<void> {
    const normalized = operations.map((operation) => normalizePendingOperation(operation, vaultId));
    const db = await openDb();
    try {
      const current = await idbRequest<unknown[]>(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll());
      const store = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME);
      const requests = [
        ...current
        .filter(isStoredPendingOperation)
        .filter((row) => row.vaultId === vaultId)
        .map((row) => store.delete(row.id)),
        ...normalized.map((entry) => store.put(entry)),
      ];
      await Promise.all(requests.map((request) => idbRequest(request)));
    } finally {
      db.close?.();
    }
  }

  async migrateLegacyLocalStorageQueue(vaultId: string): Promise<LegacyQueueMigrationResult> {
    if (typeof localStorage === 'undefined') {
      return { kind: 'blocked', reason: 'missing_storage' };
    }
    if (typeof indexedDB === 'undefined') {
      return { kind: 'blocked', reason: 'indexeddb_unavailable' };
    }

    const key = legacyStorageKey(vaultId);
    const raw = localStorage.getItem(key);
    if (!raw) {
      return { kind: 'not_needed' };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { kind: 'blocked', reason: 'malformed_legacy_queue' };
    }

    if (!Array.isArray(parsed)) {
      return { kind: 'blocked', reason: 'malformed_legacy_queue' };
    }

    const entries: PendingLocalOperation[] = [];
    for (const candidate of parsed) {
      if (!isPendingOperation(candidate, vaultId)) {
        return { kind: 'blocked', reason: 'malformed_legacy_queue' };
      }
      entries.push(normalizeLegacyPendingOperation(candidate));
    }

    await this.saveAll(vaultId, entries);
    const reloaded = await this.loadAllWithoutMigration(vaultId);
    const reloadedOpIds = new Set(reloaded.map((entry) => entry.op.opId));
    const verified = entries.every((entry) => reloadedOpIds.has(entry.op.opId));
    if (!verified) {
      return { kind: 'blocked', reason: 'verification_failed' };
    }

    localStorage.removeItem(key);
    return { kind: 'migrated', count: entries.length };
  }

  private async loadAllWithoutMigration(vaultId: string): Promise<readonly PendingLocalOperation[]> {
    const db = await openDb();
    try {
      const rows = await idbRequest<unknown[]>(db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll());
      return rows
        .filter(isStoredPendingOperation)
        .filter((row) => row.vaultId === vaultId)
        .map(stripStorageFields);
    } finally {
      db.close?.();
    }
  }
}

/**
 * Default queue persistence backed by `localStorage`.
 */
export class LocalStorageQueuePersistence implements QueuePersistence {
  async loadAll(vaultId: string): Promise<readonly PendingLocalOperation[]> {
    if (typeof localStorage === 'undefined') {
      return [];
    }
    const raw = localStorage.getItem(legacyStorageKey(vaultId));
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed.filter((entry) => isPendingOperation(entry, vaultId)).map(normalizeLegacyPendingOperation);
    } catch {
      return [];
    }
  }

  async saveAll(vaultId: string, operations: readonly PendingLocalOperation[]): Promise<void> {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage is not available; provide a custom QueuePersistence implementation');
    }
    localStorage.setItem(legacyStorageKey(vaultId), JSON.stringify(operations));
  }
}

/**
 * In-memory persistence useful for unit tests and for ephemeral
 * queues where durability is not required.
 */
export class InMemoryQueuePersistence implements QueuePersistence {
  private store = new Map<string, PendingLocalOperation[]>();

  async loadAll(vaultId: string): Promise<readonly PendingLocalOperation[]> {
    return this.store.get(vaultId) ?? [];
  }

  async saveAll(vaultId: string, operations: readonly PendingLocalOperation[]): Promise<void> {
    this.store.set(vaultId, [...operations]);
  }

  /** Test helper: wipe all stored queues. */
  clear(): void {
    this.store.clear();
  }
}

function openDb(): Promise<IDBDatabase> {
  if (typeof indexedDB === 'undefined') {
    return Promise.reject(new Error('IndexedDB is not available'));
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      const objectStoreNames = db.objectStoreNames as unknown as { contains?: (name: string) => boolean } | undefined;
      if (!objectStoreNames?.contains?.(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('failed to open pending operation queue'));
  });
}

function idbRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function isPendingOperation(value: unknown, vaultId: string): value is PendingLocalOperation {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const entry = value as PendingLocalOperation;
  return Boolean(
    entry.op
    && typeof entry.op.opId === 'string'
    && entry.op.opId.length > 0
    && entry.op.vaultId === vaultId
    && typeof entry.op.opHash === 'string'
    && entry.op.opHash.length > 0
    && typeof entry.op.signature === 'string'
    && entry.op.signature.length > 0
    && typeof entry.createdAtLocal === 'string'
    && Number.isSafeInteger(entry.retryCount)
    && isKnownPendingState(entry.state),
  );
}

function isStoredPendingOperation(value: unknown): value is StoredPendingLocalOperation {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const row = value as StoredPendingLocalOperation;
  return typeof row.id === 'string'
    && typeof row.vaultId === 'string'
    && isPendingOperation(row, row.vaultId);
}

function isKnownPendingState(state: unknown): boolean {
  return state === 'pending'
    || state === 'syncing'
    || state === 'submitted_unverified'
    || state === 'submitted_unverified_needs_verification'
    || state === 'synced'
    || state === 'failed'
    || state === 'conflict'
    || state === 'blocked_revoked'
    || state === 'rebase_needed'
    || state === 'superseded';
}

function normalizeLegacyPendingOperation(entry: PendingLocalOperation): PendingLocalOperation {
  return {
    ...entry,
    syncingStartedAtLocal: entry.syncingStartedAtLocal ?? null,
    lastSanitizedError: entry.lastSanitizedError ?? entry.lastError ?? null,
  };
}

function normalizePendingOperation(
  entry: PendingLocalOperation,
  vaultId: string,
): StoredPendingLocalOperation {
  return {
    ...normalizeLegacyPendingOperation(entry),
    id: `${vaultId}:${entry.op.opId}`,
    vaultId,
  };
}

function stripStorageFields(entry: StoredPendingLocalOperation): PendingLocalOperation {
  const { id: _id, vaultId: _vaultId, ...pending } = entry;
  return pending;
}
