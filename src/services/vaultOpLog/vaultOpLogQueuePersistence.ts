// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Persistence adapters for the local pending operation queue.
 *
 * Provides a pluggable interface so the queue logic stays
 * independent of the underlying storage technology. The default
 * implementation uses `localStorage` because it is synchronously
 * atomic per key and available in every supported environment
 * (Web, Tauri WebView).
 *
 * Limitations of the localStorage adapter (documented):
 * - Size limit (~5 MB) may be exceeded with very large queues.
 * - Synchronous JSON serialization blocks the main thread.
 * - Not as durable as IndexedDB for crash scenarios.
 *
 * Future phases can replace it with an IndexedDB adapter without
 * changing queue logic.
 */

import type { PendingLocalOperation, QueuePersistence } from './vaultOpLogPendingQueueTypes';

const STORAGE_KEY_PREFIX = 'singra:vaultOpLog:pending:' as const;

function storageKey(vaultId: string): string {
  return `${STORAGE_KEY_PREFIX}${vaultId}`;
}

/**
 * Default queue persistence backed by `localStorage`.
 */
export class LocalStorageQueuePersistence implements QueuePersistence {
  async loadAll(vaultId: string): Promise<readonly PendingLocalOperation[]> {
    if (typeof localStorage === 'undefined') {
      return [];
    }
    const raw = localStorage.getItem(storageKey(vaultId));
    if (!raw) {
      return [];
    }
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }
      return parsed as PendingLocalOperation[];
    } catch {
      return [];
    }
  }

  async saveAll(vaultId: string, operations: readonly PendingLocalOperation[]): Promise<void> {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage is not available; provide a custom QueuePersistence implementation');
    }
    localStorage.setItem(storageKey(vaultId), JSON.stringify(operations));
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
