// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `legacyMigrationStateStore` — crash-resilient persistence for the
 * migration checkpoint.
 *
 * Responsibilities:
 * - Save and load `MigrationCheckpoint` objects.
 * - Ensure checkpoint survives browser/tab crashes.
 * - Never store plaintext vault data, only record IDs and op IDs.
 *
 * Non-responsibilities:
 * - Encryption (checkpoint contains no secrets).
 * - Validation (caller validates checkpoint schema).
 */

import type { MigrationCheckpoint, MigrationState } from './migrationTypes';

const STORAGE_KEY_PREFIX = 'singra_vault_migration_checkpoint_' as const;
const COMPLETION_STORAGE_KEY_PREFIX = 'singra_vault_migration_completed_' as const;

export interface MigrationStorage {
  readonly getItem: (key: string) => string | null;
  readonly setItem: (key: string, value: string) => void;
  readonly removeItem: (key: string) => void;
}

function defaultStorage(): MigrationStorage {
  try {
    return {
      getItem: (k) => localStorage.getItem(k),
      setItem: (k, v) => localStorage.setItem(k, v),
      removeItem: (k) => localStorage.removeItem(k),
    };
  } catch {
    // Fallback for environments without localStorage (e.g. some test runners)
    const memory = new Map<string, string>();
    return {
      getItem: (k) => memory.get(k) ?? null,
      setItem: (k, v) => memory.set(k, v),
      removeItem: (k) => memory.delete(k),
    };
  }
}

function storageKey(vaultId: string): string {
  return `${STORAGE_KEY_PREFIX}${vaultId}`;
}

function completionStorageKey(vaultId: string): string {
  return `${COMPLETION_STORAGE_KEY_PREFIX}${vaultId}`;
}

export function saveMigrationCheckpoint(
  checkpoint: MigrationCheckpoint,
  storage: MigrationStorage = defaultStorage(),
): void {
  const serialized = JSON.stringify(checkpoint);
  storage.setItem(storageKey(checkpoint.vaultId), serialized);
}

export function loadMigrationCheckpoint(
  vaultId: string,
  storage: MigrationStorage = defaultStorage(),
): MigrationCheckpoint | null {
  const raw = storage.getItem(storageKey(vaultId));
  if (raw === null) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isMigrationCheckpoint(parsed)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function clearMigrationCheckpoint(
  vaultId: string,
  storage: MigrationStorage = defaultStorage(),
): void {
  storage.removeItem(storageKey(vaultId));
}

export interface MigrationCompletionMarker {
  readonly version: 1;
  readonly vaultId: string;
  readonly state: 'verified';
  readonly completedAt: string;
}

export function saveMigrationCompletionMarker(
  marker: MigrationCompletionMarker,
  storage: MigrationStorage = defaultStorage(),
): void {
  storage.setItem(completionStorageKey(marker.vaultId), JSON.stringify(marker));
}

export function loadMigrationCompletionMarker(
  vaultId: string,
  storage: MigrationStorage = defaultStorage(),
): MigrationCompletionMarker | null {
  const raw = storage.getItem(completionStorageKey(vaultId));
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isMigrationCompletionMarker(parsed)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Schema validation (defensive, does not trust storage)
// ---------------------------------------------------------------------------

function isMigrationCheckpoint(value: unknown): value is MigrationCheckpoint {
  if (!isPlainObject(value)) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  if (obj.version !== 1) {
    return false;
  }
  if (typeof obj.vaultId !== 'string' || obj.vaultId.length === 0) {
    return false;
  }
  if (typeof obj.state !== 'string' || !isMigrationState(obj.state)) {
    return false;
  }
  if (!isPlainObject(obj.legacyToNewRecordIdMap)) {
    return false;
  }
  if (!Array.isArray(obj.quarantinedLegacyIds)) {
    return false;
  }
  if (!Array.isArray(obj.committedOpIds)) {
    return false;
  }
  if (typeof obj.updatedAt !== 'string') {
    return false;
  }
  return true;
}

function isMigrationCompletionMarker(value: unknown): value is MigrationCompletionMarker {
  if (!isPlainObject(value)) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return obj.version === 1
    && typeof obj.vaultId === 'string'
    && obj.vaultId.length > 0
    && obj.state === 'verified'
    && typeof obj.completedAt === 'string';
}

const VALID_MIGRATION_STATES: Set<string> = new Set([
  'notStarted',
  'failedRetryable',
  'preflightChecked',
  'safetyFreezeActive',
  'deviceTrustPrepared',
  'preMigrationSnapshotCreated',
  'legacyRead',
  'legacyValidated',
  'legacyQuarantinePrepared',
  'newRecordsPrepared',
  'initialOperationsPrepared',
  'commitStarted',
  'commitCompleted',
  'verificationStarted',
  'verified',
  'failedBlocked',
  'rolledBack',
  'legacyMarkedMigrated',
]);

function isMigrationState(value: unknown): value is MigrationState {
  return typeof value === 'string' && VALID_MIGRATION_STATES.has(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
