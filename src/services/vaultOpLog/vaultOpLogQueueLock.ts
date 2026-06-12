// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Multi-tab / multi-instance locking for the pending operation queue.
 *
 * The Web platform provides `navigator.locks` (Web Locks API) which
 * is the preferred mechanism. For Tauri or older environments a
 * `localStorage` leader-election token is used as a fallback.
 *
 * Phase 4 ships both implementations plus an in-memory fallback for
 * testing. Real multi-tab hardening is documented as a rest task
 * for Phase 8 if `navigator.locks` coverage across all target
 * browsers is not yet confirmed.
 */

import { randomUuid } from '@dis/shield/random';

const LOCK_PREFIX = 'singra-vault/op-log/' as const;
const LEADER_KEY_PREFIX = 'singra:vaultOpLog:leader:' as const;
const LEADER_TTL_MS = 5000 as const;

export interface QueueLock {
  /**
   * Acquire a lock scoped to `vaultId`, execute `fn`, and release.
   * The lock must be exclusive: at most one caller per vaultId
   * across all tabs / instances.
   */
  acquire<T>(vaultId: string, fn: () => Promise<T>): Promise<T>;
}

/**
 * Web Locks API implementation.
 *
 * Requires `navigator.locks`. Falls back to `LocalStorageLeaderQueueLock`
 * if the API is unavailable.
 */
export class WebLocksQueueLock implements QueueLock {
  private fallback: QueueLock | null = null;

  async acquire<T>(vaultId: string, fn: () => Promise<T>): Promise<T> {
    if (typeof navigator !== 'undefined' && navigator.locks) {
      return navigator.locks.request(`${LOCK_PREFIX}${vaultId}`, fn);
    }
    if (!this.fallback) {
      this.fallback = new LocalStorageLeaderQueueLock();
    }
    return this.fallback.acquire(vaultId, fn);
  }
}

/**
 * Simple leader-election via `localStorage` token.
 *
 * A token with a timestamp is written before executing `fn`. If
 * another instance sees a recent token, it waits briefly and
 * retries once. This is **best effort**; it reduces but does not
 * eliminate race conditions between very fast concurrent writers.
 *
 * For Tauri, this is acceptable because there is typically only
 * one window per origin. For multi-tab Web, prefer `WebLocksQueueLock`.
 */
export class LocalStorageLeaderQueueLock implements QueueLock {
  async acquire<T>(vaultId: string, fn: () => Promise<T>): Promise<T> {
    if (typeof localStorage === 'undefined') {
      // No storage available — run unprotected. This only happens in
      // test or headless environments where the in-memory lock is
      // the appropriate substitute.
      return fn();
    }

    const key = `${LEADER_KEY_PREFIX}${vaultId}`;

    const now = Date.now();
    const raw = localStorage.getItem(key);
    if (raw) {
      try {
        const existing = JSON.parse(raw) as { ts: number; id: string };
        if (now - existing.ts < LEADER_TTL_MS) {
          // Another instance holds the lock. Wait and retry once.
          await sleep(LEADER_TTL_MS);
        }
      } catch {
        // Invalid token — ignore and proceed.
      }
    }

    const id = generateLockId();
    localStorage.setItem(key, JSON.stringify({ ts: now, id }));

    try {
      return await fn();
    } finally {
      // Only remove our own token. If another instance raced and
      // replaced it, leave it alone.
      const current = localStorage.getItem(key);
      if (current) {
        try {
          const parsed = JSON.parse(current) as { ts: number; id: string };
          if (parsed.id === id) {
            localStorage.removeItem(key);
          }
        } catch {
          // Ignore parse errors during cleanup.
        }
      }
    }
  }
}

/**
 * In-memory lock for unit tests and single-process environments.
 * Does **not** protect against other tabs or OS processes.
 */
export class InMemoryQueueLock implements QueueLock {
  private locks = new Map<string, Promise<unknown>>();

  async acquire<T>(vaultId: string, fn: () => Promise<T>): Promise<T> {
    const key = `${LOCK_PREFIX}${vaultId}`;

    // Chain behind any existing promise for this vault.
    // Catch and swallow rejections so the chain never breaks.
    const previous = this.locks.get(key) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(async () => fn());
    this.locks.set(key, next);

    try {
      return await next;
    } finally {
      // Clean up only if no one else queued behind us.
      const current = this.locks.get(key);
      if (current === next) {
        this.locks.delete(key);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function generateLockId(): string {
  // Powered by DIS: CSPRNG-backed UUID with a secure byte fallback —
  // never Math.random.
  return randomUuid();
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
