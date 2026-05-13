// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Domain types for the local pending operation queue (Phase 4).
 *
 * A pending queue entry is only valid when the operation is fully
 * signed and the optional record payload is sealed. No plaintext
 * is stored.
 */

import type { VaultOperationRow, VaultRecordRow } from './vaultOpLogRpcTypes';

export type PendingOperationState =
  | 'pending'
  | 'syncing'
  | 'submitted_unverified'
  | 'submitted_unverified_needs_verification'
  | 'synced'
  | 'failed'
  | 'conflict'
  | 'blocked_revoked'
  | 'rebase_needed'
  | 'superseded';

/**
 * A single entry in the local pending operation queue.
 *
 * Invariants enforced by the queue layer:
 * - `op.signature` is non-empty.
 * - `op.opHash` is non-empty.
 * - `op.intentId` is non-empty.
 * - `record` is null only for device-trust operations or if the
 *   operation type does not carry a record payload (e.g. future
 *   `revoke_device` without a trust record envelope).
 * - `lastError` never contains secrets; it is sanitized before
 *   storage.
 */
export interface PendingLocalOperation {
  readonly op: VaultOperationRow;
  readonly record: VaultRecordRow | null;
  readonly createdAtLocal: string;
  readonly retryCount: number;
  readonly lastError: string | null;
  readonly lastSanitizedError?: string | null;
  readonly state: PendingOperationState;
}

/**
 * Result of classifying a `submit_vault_operation` RPC response
 * from the perspective of the pending queue.
 */
export type ClassifiedSubmitResult =
  | { readonly kind: 'submittedUnverified'; readonly resultingVaultHead: string }
  | { readonly kind: 'idempotentSubmittedUnverified'; readonly resultingVaultHead: string }
  | { readonly kind: 'retryable'; readonly error: string }
  | { readonly kind: 'rebaseNeeded' }
  | { readonly kind: 'recordConflict' }
  | { readonly kind: 'permanentFailed'; readonly error: string };

/**
 * Interface for queue persistence. Implementations must be
 * atomic per `saveAll` call (best effort given the underlying
 * storage).
 */
export interface QueuePersistence {
  loadAll(vaultId: string): Promise<readonly PendingLocalOperation[]>;
  saveAll(vaultId: string, operations: readonly PendingLocalOperation[]): Promise<void>;
}
