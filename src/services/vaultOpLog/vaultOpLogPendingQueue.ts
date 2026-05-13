// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Local pending operation queue with state transitions, retry
 * classification and crash recovery (Phase 4).
 *
 * The queue stores only signed operations and sealed records.
 * No plaintext persists. State transitions are deterministic and
 * tested.
 */

import type { SubmitVaultOperationResult } from './vaultOpLogRpcTypes';
import type {
  ClassifiedSubmitResult,
  PendingLocalOperation,
  PendingOperationState,
  QueuePersistence,
} from './vaultOpLogPendingQueueTypes';
import type { BuiltVaultOperation } from './vaultOpLogOperationBuilder';
import { toVaultOperationRow, toVaultRecordRow } from './vaultOpLogOperationBuilder';

export class VaultOpLogPendingQueue {
  private operations: PendingLocalOperation[] = [];

  constructor(
    private readonly vaultId: string,
    private readonly persistence: QueuePersistence,
  ) {}

  async load(): Promise<void> {
    const loaded = await this.persistence.loadAll(this.vaultId);
    this.operations = [...loaded];
  }

  async save(): Promise<void> {
    await this.persistence.saveAll(this.vaultId, this.operations);
  }

  getOperations(): readonly PendingLocalOperation[] {
    return this.operations;
  }

  async enqueue(built: BuiltVaultOperation): Promise<void> {
    const opRow = toVaultOperationRow(built);
    const isTombstone = built.signedOperation.body.opType === 'delete';
    const recRow = toVaultRecordRow(built.sealedRecord, opRow, isTombstone);
    const entry: PendingLocalOperation = {
      op: opRow,
      record: recRow,
      createdAtLocal: new Date().toISOString(),
      retryCount: 0,
      lastError: null,
      lastSanitizedError: null,
      state: 'pending',
    };
    this.operations = [...this.operations, entry];
    await this.save();
  }

  async markSyncing(opId: string): Promise<void> {
    this.operations = transitionOp(this.operations, opId, 'syncing');
    await this.save();
  }

  async markSynced(opId: string, resultingVaultHead: string): Promise<void> {
    this.operations = this.operations.map((e) =>
      e.op.opId === opId
        ? { ...e, state: 'synced' as PendingOperationState, op: { ...e.op, resultingVaultHead } }
        : e,
    );
    await this.save();
  }

  async markSubmittedUnverified(opId: string, resultingVaultHead: string): Promise<void> {
    this.operations = this.operations.map((e) =>
      e.op.opId === opId
        ? { ...e, state: 'submitted_unverified' as PendingOperationState, op: { ...e.op, resultingVaultHead }, lastError: null, lastSanitizedError: null }
        : e,
    );
    await this.save();
  }

  async markSubmittedUnverifiedNeedsVerification(opId: string, error: string): Promise<void> {
    const sanitized = sanitizeQueueErrorForStorage(error);
    this.operations = this.operations.map((e) =>
      e.op.opId === opId
        ? {
            ...e,
            state: 'submitted_unverified_needs_verification' as PendingOperationState,
            lastError: sanitized,
            lastSanitizedError: sanitized,
          }
        : e,
    );
    await this.save();
  }

  async markRetryable(opId: string, error: string): Promise<void> {
    const sanitized = sanitizeQueueErrorForStorage(error);
    this.operations = this.operations.map((e) =>
      e.op.opId === opId
        ? { ...e, state: 'pending' as PendingOperationState, retryCount: e.retryCount + 1, lastError: sanitized, lastSanitizedError: sanitized }
        : e,
    );
    await this.save();
  }

  async markRebaseNeeded(opId: string): Promise<void> {
    this.operations = transitionOp(this.operations, opId, 'rebase_needed');
    await this.save();
  }

  async markConflict(opId: string, error?: string): Promise<void> {
    const sanitized = error ? sanitizeQueueErrorForStorage(error) : null;
    this.operations = this.operations.map((e) =>
      e.op.opId === opId ? { ...e, state: 'conflict' as PendingOperationState, lastError: sanitized, lastSanitizedError: sanitized } : e,
    );
    await this.save();
  }

  async markBlockedRevoked(opId: string, error = 'device_revoked'): Promise<void> {
    const sanitized = sanitizeQueueErrorForStorage(error);
    this.operations = this.operations.map((e) =>
      e.op.opId === opId ? { ...e, state: 'blocked_revoked' as PendingOperationState, lastError: sanitized, lastSanitizedError: sanitized } : e,
    );
    await this.save();
  }

  async blockAllForRevokedDevice(authorDeviceId: string): Promise<void> {
    this.operations = this.operations.map((e) =>
      e.op.authorDeviceId === authorDeviceId
      && (e.state === 'pending' || e.state === 'syncing' || e.state === 'submitted_unverified')
        ? {
            ...e,
            state: 'blocked_revoked' as PendingOperationState,
            lastError: 'device_revoked',
            lastSanitizedError: 'device_revoked',
          }
        : e,
    );
    await this.save();
  }

  async markSuperseded(opId: string): Promise<void> {
    this.operations = transitionOp(this.operations, opId, 'superseded');
    await this.save();
  }

  async markFailed(opId: string, error: string): Promise<void> {
    const sanitized = sanitizeQueueErrorForStorage(error);
    this.operations = this.operations.map((e) =>
      e.op.opId === opId ? { ...e, state: 'failed' as PendingOperationState, lastError: sanitized, lastSanitizedError: sanitized } : e,
    );
    await this.save();
  }

  getPending(): readonly PendingLocalOperation[] {
    return this.operations.filter((e) => e.state === 'pending');
  }

  getSyncing(): readonly PendingLocalOperation[] {
    return this.operations.filter((e) => e.state === 'syncing');
  }

  getRebaseNeeded(): readonly PendingLocalOperation[] {
    return this.operations.filter((e) => e.state === 'rebase_needed');
  }

  getSubmittedUnverified(): readonly PendingLocalOperation[] {
    return this.operations.filter((e) => e.state === 'submitted_unverified');
  }

  /**
   * After a crash, any `syncing` entry may have been partially
   * committed (the RPC is idempotent) or not. We conservatively
   * roll them back to `pending` with a diagnostic lastError so the
   * next retry attempt can resolve the state via the server.
   */
  async recoverAfterCrash(): Promise<void> {
    this.operations = this.operations.map((e) =>
      e.state === 'syncing'
        ? {
            ...e,
            state: 'pending' as PendingOperationState,
            retryCount: e.retryCount + 1,
            lastError: 'recovered_from_crash: operation was syncing when app terminated',
            lastSanitizedError: 'recovered_from_crash: operation was syncing when app terminated',
          }
        : e,
    );
    await this.save();
  }
}

// ---------------------------------------------------------------------------
// Pure state-transition helpers
// ---------------------------------------------------------------------------

function transitionOp(
  ops: PendingLocalOperation[],
  opId: string,
  newState: PendingOperationState,
): PendingLocalOperation[] {
  const found = ops.some((e) => e.op.opId === opId);
  if (!found) {
    throw new Error(`pending operation ${opId} not found in queue`);
  }
  return ops.map((e) => (e.op.opId === opId ? { ...e, state: newState } : e));
}

/**
 * Sanitize an error before writing it into queue storage.
 * Removes anything that could be a secret, stack trace or
 * ciphertext fragment.
 */
export function sanitizeQueueErrorForStorage(error: string | Error | unknown): string {
  if (error instanceof Error) {
    return sanitizeQueueErrorForStorage(error.message);
  }
  const raw = typeof error === 'string' ? error : JSON.stringify(error);
  // Strip base64-like strings (could be ciphertext, signatures, keys).
  const cleaned = raw.replace(/[A-Za-z0-9_-]{40,}/g, '<redacted>');
  // Truncate to avoid unbounded storage growth.
  return cleaned.length > 500 ? `${cleaned.slice(0, 500)}...<truncated>` : cleaned;
}

/**
 * Classify a `SubmitVaultOperationResult` from the repository into
 * a queue action.
 */
export function classifySubmitResult(
  result: SubmitVaultOperationResult,
): ClassifiedSubmitResult {
  switch (result.kind) {
    case 'applied': {
      if (result.idempotent) {
        return { kind: 'idempotentSubmittedUnverified', resultingVaultHead: result.resultingVaultHead };
      }
      return { kind: 'submittedUnverified', resultingVaultHead: result.resultingVaultHead };
    }
    case 'rebaseNeeded':
      return { kind: 'rebaseNeeded' };
    case 'recordConflictStaleVersion':
    case 'recordConflictStaleCiphertextHash':
    case 'recordTypeMismatch':
    case 'recordAlreadyExists':
    case 'createMustNotCarryBase':
      return { kind: 'recordConflict' };
    case 'recordNotFound':
      return { kind: 'permanentFailed', error: `recordNotFound: ${result.kind}` };
    case 'duplicateOpIdDifferentHash':
      return { kind: 'permanentFailed', error: 'duplicateOpIdDifferentHash: security event' };
    case 'unauthorized':
      return { kind: 'permanentFailed', error: 'unauthorized: session expired or revoked' };
    case 'vaultOwnershipError':
      return { kind: 'permanentFailed', error: 'vaultOwnershipError' };
    case 'rpcError':
      return { kind: 'retryable', error: `rpcError ${result.code}` };
    case 'malformedResponse':
      return { kind: 'permanentFailed', error: `malformedResponse: ${result.reason}` };
    default:
      return { kind: 'permanentFailed', error: `unrecognized result kind` };
  }
}
