// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Domain types for Phase 7 — Legacy-to-Operation-Log migration.
 *
 * All types are designed to be serialisable, testable and free of
 * secrets in their string representations.  Plaintext vault data
 * never appears in these types; only references, hashes and
 * classifications.
 *
 * Threat model (inline, because it governs every field):
 * - Assets: passwords, vault entries, categories, vault encryption key,
 *   device signing key, recovery/snapshot data, tokens, metadata, logs.
 * - Trust boundaries: Web-Client, Tauri-Client, Supabase/Auth, DB,
 *   RPC-layer, local storage, snapshot store, browser/extension edges.
 * - Data lifecycle: legacy-read → decrypt → validate → quarantine →
 *   re-encrypt → sign → commit → verify → snapshot → retry/rollback.
 * - Risks: secret leaks in logs, metadata leaks, replay, rollback,
 *   downgrade, partial migration, double commit, weak recovery,
 *   wrong device trust, faulty category mapping.
 */

// ---------------------------------------------------------------------------
// Migration state machine
// ---------------------------------------------------------------------------

export const MIGRATION_STATES = [
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
] as const;

export type MigrationState = (typeof MIGRATION_STATES)[number];

// ---------------------------------------------------------------------------
// Legacy quarantine reasons
// ---------------------------------------------------------------------------

export const LEGACY_QUARANTINE_REASONS = [
  'legacyDecryptFailed',
  'legacyInvalidSchema',
  'legacyMissingRequiredField',
  'legacyUnsupportedVersion',
  'legacyCategoryMappingFailed',
] as const;

export type LegacyQuarantineReason = (typeof LEGACY_QUARANTINE_REASONS)[number];

// ---------------------------------------------------------------------------
// Migration error classification
// ---------------------------------------------------------------------------

export type MigrationErrorKind =
  | 'preflightFailed'
  | 'snapshotFailed'
  | 'legacyReadFailed'
  | 'legacyValidationFailed'
  | 'recordPreparationFailed'
  | 'operationPreparationFailed'
  | 'deviceTrustBootstrapFailed'
  | 'commitFailed'
  | 'verificationFailed'
  | 'rollbackFailed'
  | 'markMigratedFailed';

export interface MigrationError {
  readonly kind: MigrationErrorKind;
  readonly message: string;
  readonly stateAtError: MigrationState;
  /** Whether the migration may be retried from the last persisted state. */
  readonly retryable: boolean;
}

// ---------------------------------------------------------------------------
// Legacy source data (abstract interfaces — no secrets)
// ---------------------------------------------------------------------------

/**
 * A legacy vault item row as read from the old `vault_items` table.
 * `encryptedData` is the ciphertext string; the actual plaintext is
 * never stored in this shape.
 */
export interface LegacyVaultItemRow {
  readonly id: string;
  readonly userId: string;
  readonly vaultId: string;
  readonly categoryId: string | null;
  readonly encryptedData: string;
  readonly title: string;
  readonly websiteUrl: string | null;
  readonly itemType: string;
  readonly isFavorite: boolean | null;
  readonly sortOrder: number | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * A legacy category row as read from the old `categories` table.
 * In the legacy system categories are stored unencrypted.
 */
export interface LegacyCategoryRow {
  readonly id: string;
  readonly userId: string;
  readonly name: string;
  readonly color: string | null;
  readonly icon: string | null;
  readonly parentId: string | null;
  readonly sortOrder: number | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

// ---------------------------------------------------------------------------
// Validation results
// ---------------------------------------------------------------------------

export interface ValidatedLegacyItem {
  readonly legacyId: string;
  readonly categoryId: string | null;
  readonly decryptedData: unknown; // caller must cast to VaultItemData after validation
  readonly legacyEncryptedData: string;
}

export interface LegacyItemValidationFailure {
  readonly legacyId: string;
  readonly reason: LegacyQuarantineReason;
  readonly detail: string;
}

export interface ValidatedLegacyCategory {
  readonly legacyId: string;
  readonly name: string;
  readonly color: string | null;
  readonly icon: string | null;
  readonly parentId: string | null;
  readonly sortOrder: number | null;
}

export interface LegacyCategoryValidationFailure {
  readonly legacyId: string;
  readonly reason: LegacyQuarantineReason;
  readonly detail: string;
}

// ---------------------------------------------------------------------------
// Migration batch (prepared but not yet committed)
// ---------------------------------------------------------------------------

/**
 * A prepared category record ready to be committed as a `create`
 * operation.  The plaintext bytes are kept only transiently in the
 * orchestrator and wiped after sealing.
 */
export interface PreparedCategoryMigration {
  readonly newRecordId: string;
  readonly legacyId: string;
  readonly plaintext: Uint8Array;
}

/**
 * A prepared item record ready to be committed as a `create`
 * operation.  The plaintext contains the mapped category id.
 */
export interface PreparedItemMigration {
  readonly newRecordId: string;
  readonly legacyId: string;
  readonly plaintext: Uint8Array;
}

// ---------------------------------------------------------------------------
// Migration progress / persistence
// ---------------------------------------------------------------------------

export interface MigrationProgress {
  readonly state: MigrationState;
  readonly vaultId: string;
  readonly deviceId: string | null;
  readonly snapshotId: string | null;
  readonly legacyItemCount: number;
  readonly legacyCategoryCount: number;
  readonly quarantinedItemCount: number;
  readonly quarantinedCategoryCount: number;
  readonly preparedItemCount: number;
  readonly preparedCategoryCount: number;
  readonly committedOperationCount: number;
  readonly error: MigrationError | null;
  readonly startedAt: string | null;
  readonly completedAt: string | null;
}

// ---------------------------------------------------------------------------
// Migration service inputs / outputs
// ---------------------------------------------------------------------------

export interface RunMigrationInput {
  readonly vaultId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly publicSigningKeyB64Url: string;
  readonly vaultEncryptionKey: Uint8Array;
  readonly legacyItems: readonly LegacyVaultItemRow[];
  readonly legacyCategories: readonly LegacyCategoryRow[];
  readonly decryptItem: (legacyItem: LegacyVaultItemRow) => Promise<unknown>;
  readonly rpcClient: import('./vaultOpLogRepository').SupabaseRpcClient;
  readonly trustedSnapshotService: {
    createSnapshot(input: unknown): Promise<unknown>;
  };
  readonly featureFlagEnabled: boolean;
  readonly now?: string;
}

export interface RunMigrationResult {
  readonly success: boolean;
  readonly finalState: MigrationState;
  readonly progress: MigrationProgress;
  readonly error: MigrationError | null;
}

// ---------------------------------------------------------------------------
// Idempotency / crash recovery
// ---------------------------------------------------------------------------

/**
 * A persisted migration checkpoint.  The orchestrator writes this
 * after every state transition so that a crash can be recovered.
 */
export interface MigrationCheckpoint {
  readonly version: 1;
  readonly vaultId: string;
  readonly state: MigrationState;
  readonly snapshotId: string | null;
  readonly legacyToNewRecordIdMap: Record<string, string>;
  readonly quarantinedLegacyIds: readonly string[];
  readonly committedOpIds: readonly string[];
  readonly error: MigrationError | null;
  readonly updatedAt: string;
}
