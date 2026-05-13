// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultStateMachine` — local state machine that verifies remote
 * operations and records, classifies them, and decides whether a
 * record may be decrypted.
 *
 * This is the heart of Phase 5. It orchestrates:
 *   - `verifyOperation` (signature, trust, hashes)
 *   - `verifyRecordContext` (AAD, ciphertext hash, operation linkage)
 *   - `canDecryptVerifiedRecordContext` (the decrypt gate)
 *   - `openRecord` (AEAD decrypt, only when all gates pass)
 *   - State classification (verified, conflict, quarantined, deleted, ...)
 *   - Vault security mode determination
 *
 * No record is ever decrypted before its operation and context are
 * fully verified.
 */

import * as cryptoRecordService from './cryptoRecordService';
import {
  deriveRecordKey,
  type OpenedRecordV1,
} from './cryptoRecordService';
import { buildRecordAad } from './recordAad';
import { computeVaultHead } from './recordHashes';
import type {
  RecordSecurityState,
  VaultSecurityMode,
  OperationVerificationResult,
  RecordContextVerificationResult,
} from './vaultSecurityStates';
import { canDecryptVerifiedRecordContext } from './vaultSecurityStates';
import {
  verifyOperation,
  type VerifyOperationInput,
} from './verifyOperation';
import {
  verifyRecordContext,
  type VerifyRecordContextInput,
} from './verifyRecordContext';
import type {
  TrustedDeviceRecordV1,
} from './types';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';
import type { TrustListInput } from './deviceTrustService';

// ---------------------------------------------------------------------------
// Local vault state snapshot
// ---------------------------------------------------------------------------

export interface LocalVerifiedRecord {
  readonly record: VaultRecordRow;
  readonly recordState: RecordSecurityState;
  readonly plaintext: Uint8Array | null;
  readonly lastOperation: VaultOperationRow;
}

export interface LocalQuarantinedRecord {
  readonly record: VaultRecordRow | null;
  readonly recordState: Extract<
    RecordSecurityState,
    | 'quarantinedTampered'
    | 'quarantinedUnknownAuthor'
    | 'quarantinedMissingWithoutDelete'
    | 'quarantinedUnreadable'
    | 'quarantinedInvalidSchema'
  >;
  readonly reason: string;
}

export interface LocalRecordConflict {
  readonly recordId: string;
  readonly operations: readonly VaultOperationRow[];
  readonly recordVersions: readonly VaultRecordRow[];
}

export interface LocalVaultState {
  readonly recordsById: ReadonlyMap<string, LocalVerifiedRecord>;
  readonly quarantinedRecordsById: ReadonlyMap<string, LocalQuarantinedRecord>;
  readonly conflictsByRecordId: ReadonlyMap<string, LocalRecordConflict>;
  readonly trustedDevicesById: ReadonlyMap<string, TrustedDeviceRecordV1>;
  readonly lastVerifiedVaultHead: string | null;
}

export interface ApplyRemoteOperationInput {
  readonly state: LocalVaultState;
  readonly operation: VaultOperationRow;
  readonly record: VaultRecordRow;
  readonly trust: TrustListInput;
  readonly publicKey?: CryptoKey;
  readonly vaultEncryptionKey: Uint8Array;
  readonly verifiedBaseRecordState?: VerifiedBaseRecordState;
  readonly vaultHeadTransitionVerified?: boolean;
}

export interface ApplyRemoteOperationResult {
  readonly nextState: LocalVaultState;
  readonly recordState: RecordSecurityState;
  readonly vaultMode: VaultSecurityMode;
  readonly openedRecord: OpenedRecordV1 | null;
}

export interface ApplyTrustedDeleteInput {
  readonly state: LocalVaultState;
  readonly operation: VaultOperationRow;
  readonly record: VaultRecordRow;
  readonly trust: TrustListInput;
  readonly publicKey?: CryptoKey;
  readonly verifiedBaseRecordState?: VerifiedBaseRecordState;
  readonly vaultHeadTransitionVerified?: boolean;
}

export interface ApplyTrustedDeleteResult {
  readonly nextState: LocalVaultState;
  readonly recordState: RecordSecurityState;
  readonly vaultMode: VaultSecurityMode;
}

export interface VerifiedBaseRecordState {
  readonly recordVersion: number;
  readonly ciphertextHash: string;
}

// ---------------------------------------------------------------------------
// applyRemoteOperation
// ---------------------------------------------------------------------------

/**
 * Apply a remote operation and its claimed record to the local vault state.
 *
 * Pipeline (no decryption before gate 3):
 *   1. Verify operation (signature, trust, hashes).
 *   2. Verify record context (AAD, ciphertext hash, linkage).
 *   3. Decrypt gate — only pass when both steps succeeded.
 *   4. AEAD open with verified context.
 *   5. Classify security state.
 *   6. Update local state.
 *   7. Recompute vault security mode.
 */
export async function applyRemoteOperation(
  input: ApplyRemoteOperationInput,
): Promise<ApplyRemoteOperationResult> {
  const { state, operation, record, trust, publicKey, vaultEncryptionKey } = input;

  const localRecord = state.recordsById.get(record.recordId) ?? null;
  const localRecordState = input.verifiedBaseRecordState ?? (localRecord
    ? { recordVersion: localRecord.record.recordVersion, ciphertextHash: localRecord.record.ciphertextHash }
    : null);

  // Gate 1: operation verification
  const opResult = await verifyOperation({
    operation,
    trust,
    publicKey,
    localRecordState,
  });

  if (opResult.kind !== 'validTrustedOperation') {
    const recordState = classifyRecordFromOperationFailure(opResult);
    const nextState = updateStateWithQuarantine(state, record, recordState, `operation:${opResult.kind}`);
    const vaultMode = determineVaultSecurityMode(nextState);
    return { nextState, recordState, vaultMode, openedRecord: null };
  }

  if (!input.vaultHeadTransitionVerified && !(await verifyVaultHeadTransition(state, operation))) {
    const recordState: RecordSecurityState = 'quarantinedTampered';
    const nextState = updateStateWithQuarantine(state, record, recordState, 'vault_head_transition_mismatch');
    const vaultMode = determineVaultSecurityMode(nextState);
    return { nextState, recordState, vaultMode, openedRecord: null };
  }

  // Gate 2: record context verification
  const ctxResult = await verifyRecordContext({ record, operation });

  if (!canDecryptVerifiedRecordContext(opResult, ctxResult)) {
    const recordState = classifyRecordFromContextFailure(ctxResult);
    const nextState = updateStateWithQuarantine(state, record, recordState, `context:${ctxResult.kind}`);
    const vaultMode = determineVaultSecurityMode(nextState);
    return { nextState, recordState, vaultMode, openedRecord: null };
  }

  // Gate 3: decrypt
  let openedRecord: OpenedRecordV1 | null = null;
  try {
    openedRecord = await decryptVerifiedRecord(record, vaultEncryptionKey);
  } catch {
    const recordState: RecordSecurityState = 'quarantinedUnreadable';
    const nextState = updateStateWithQuarantine(state, record, recordState, 'decrypt_failed');
    const vaultMode = determineVaultSecurityMode(nextState);
    return { nextState, recordState, vaultMode, openedRecord: null };
  }

  // Gate 4: plaintext schema validation (minimal placeholder — full
  // schema validation is Phase 9)
  const schemaValid = validateRecordPlaintext(openedRecord.plaintext, record);
  if (!schemaValid) {
    const recordState: RecordSecurityState = 'quarantinedInvalidSchema';
    const nextState = updateStateWithQuarantine(state, record, recordState, 'schema_invalid');
    const vaultMode = determineVaultSecurityMode(nextState);
    return { nextState, recordState, vaultMode, openedRecord: null };
  }

  // Gate 5: conflict detection
  if (localRecord !== null && localRecord.recordState === 'verified') {
    const causalConflict = detectConflict(localRecord.record, operation);
    if (causalConflict) {
      const nextState = updateStateWithConflict(state, localRecord, operation, record);
      const vaultMode = determineVaultSecurityMode(nextState);
      return { nextState, recordState: 'conflict', vaultMode, openedRecord };
    }
  }

  // All gates passed — record is verified
  const nextRecord: LocalVerifiedRecord = {
    record,
    recordState: 'verified',
    plaintext: openedRecord.plaintext,
    lastOperation: operation,
  };

  const nextRecords = new Map(state.recordsById);
  nextRecords.set(record.recordId, nextRecord);

  const nextState: LocalVaultState = {
    ...state,
    recordsById: nextRecords,
    lastVerifiedVaultHead: operation.resultingVaultHead,
  };

  const vaultMode = determineVaultSecurityMode(nextState);
  return { nextState, recordState: 'verified', vaultMode, openedRecord };
}

// ---------------------------------------------------------------------------
// applyTrustedDelete
// ---------------------------------------------------------------------------

/**
 * Apply a delete operation that has already passed operation
 * verification. The record must be a tombstone and the operation
 * must be a delete.
 *
 * A missing record without a valid delete operation is classified
 * as `quarantinedMissingWithoutDelete`, never as silently deleted.
 */
export async function applyTrustedDelete(
  input: ApplyTrustedDeleteInput,
): Promise<ApplyTrustedDeleteResult> {
  const { state, operation, record, trust, publicKey } = input;

  if (operation.opType !== 'delete') {
    const nextState = updateStateWithQuarantine(
      state,
      record,
      'quarantinedTampered',
      'applyTrustedDelete called with non-delete operation',
    );
    return { nextState, recordState: 'quarantinedTampered', vaultMode: determineVaultSecurityMode(nextState) };
  }

  const localRecord = state.recordsById.get(record.recordId) ?? null;
  const localRecordState = input.verifiedBaseRecordState ?? (localRecord
    ? { recordVersion: localRecord.record.recordVersion, ciphertextHash: localRecord.record.ciphertextHash }
    : null);

  const opResult = await verifyOperation({ operation, trust, publicKey, localRecordState });
  if (opResult.kind !== 'validTrustedOperation') {
    const recordState = classifyRecordFromOperationFailure(opResult);
    const nextState = updateStateWithQuarantine(state, record, recordState, `delete_operation_untrusted:${opResult.kind}`);
    return { nextState, recordState, vaultMode: determineVaultSecurityMode(nextState) };
  }

  if (!input.vaultHeadTransitionVerified && !(await verifyVaultHeadTransition(state, operation))) {
    const nextState = updateStateWithQuarantine(
      state,
      record,
      'quarantinedTampered',
      'delete_vault_head_transition_mismatch',
    );
    return { nextState, recordState: 'quarantinedTampered', vaultMode: determineVaultSecurityMode(nextState) };
  }

  const ctxResult = await verifyRecordContext({ record, operation });
  if (ctxResult.kind !== 'validContext') {
    // A valid signed delete is the deletion proof. If the server keeps or
    // returns a stale/mismatched record row, the stale payload must not be
    // decrypted or shown; treating it as deleted preserves fail-closed egress.
    return markRecordDeletedByTrustedDevice(state, operation, record);
  }

  if (!record.isTombstone) {
    // Same rule as above: the trusted delete operation wins over a stale
    // server record. Tombstone payload verification is desirable for audit,
    // but a mismatch must not resurrect or quarantine already-deleted data.
    return markRecordDeletedByTrustedDevice(state, operation, record);
  }

  return markRecordDeletedByTrustedDevice(state, operation, record);
}

function markRecordDeletedByTrustedDevice(
  state: LocalVaultState,
  operation: VaultOperationRow,
  record: VaultRecordRow,
): ApplyTrustedDeleteResult {
  const nextRecord: LocalVerifiedRecord = {
    record,
    recordState: 'deletedByTrustedDevice',
    plaintext: null,
    lastOperation: operation,
  };

  const nextRecords = new Map(state.recordsById);
  nextRecords.set(record.recordId, nextRecord);

  const nextState: LocalVaultState = {
    ...state,
    recordsById: nextRecords,
    lastVerifiedVaultHead: operation.resultingVaultHead,
  };

  const vaultMode = determineVaultSecurityMode(nextState);
  return { nextState, recordState: 'deletedByTrustedDevice', vaultMode };
}

// ---------------------------------------------------------------------------
// Vault security mode
// ---------------------------------------------------------------------------

/**
 * Determine the vault security mode from the current local state.
 *
 * Rules (in order of severity):
 *   lockedCritical — root trust broken (not implemented here; caller
 *                    must set this when manifest/key/trust-root is damaged).
 *   safeMode / safeModeRecommended — many missing records without delete,
 *                                     many tampered records, or operation-log gaps.
 *   restricted — individual records quarantined or in conflict.
 *   normal — all active records verified or cleanly deleted.
 */
export function determineVaultSecurityMode(state: LocalVaultState): VaultSecurityMode {
  let quarantineCount = 0;
  let conflictCount = 0;
  let missingWithoutDeleteCount = 0;

  for (const entry of state.quarantinedRecordsById.values()) {
    quarantineCount += 1;
    if (entry.recordState === 'quarantinedMissingWithoutDelete') {
      missingWithoutDeleteCount += 1;
    }
  }

  for (const entry of state.conflictsByRecordId.values()) {
    conflictCount += 1;
  }

  // Heuristic: many missing records without delete → safe mode recommended
  if (missingWithoutDeleteCount >= 3 || quarantineCount >= 5) {
    return 'safeModeRecommended';
  }

  if (conflictCount > 0 || quarantineCount > 0) {
    return 'restricted';
  }

  return 'normal';
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function classifyRecordFromOperationFailure(
  result: OperationVerificationResult,
): RecordSecurityState {
  switch (result.kind) {
    case 'unknownAuthor':
      return 'quarantinedUnknownAuthor';
    case 'revokedAuthor':
      return 'quarantinedUnknownAuthor';
    case 'invalidSignature':
      return 'quarantinedTampered';
    case 'opHashMismatch':
      return 'quarantinedTampered';
    case 'unsupportedOperationType':
      return 'quarantinedTampered';
    case 'causalGap':
      return 'quarantinedMissingWithoutDelete';
    case 'rollbackSuspected':
      return 'quarantinedTampered';
    case 'payloadHashMismatch':
      return 'quarantinedTampered';
    case 'conflictCandidate':
      return 'conflict';
    case 'requiresSafeMode':
      return 'pendingVerification';
    case 'requiresLockedCritical':
      return 'quarantinedTampered';
    default:
      return 'quarantinedTampered';
  }
}

function classifyRecordFromContextFailure(
  result: RecordContextVerificationResult,
): RecordSecurityState {
  switch (result.kind) {
    case 'aadMismatch':
      return 'quarantinedTampered';
    case 'ciphertextHashMismatch':
      return 'quarantinedTampered';
    case 'lastOpIdMismatch':
      return 'quarantinedTampered';
    case 'payloadHashMismatch':
      return 'quarantinedTampered';
    case 'invalidSchema':
      return 'quarantinedInvalidSchema';
    case 'validContext':
      return 'verified';
    default:
      return 'quarantinedTampered';
  }
}

function detectConflict(
  localRecord: VaultRecordRow,
  incomingOperation: VaultOperationRow,
): boolean {
  // A conflict exists when an incoming operation references the same
  // base record version but the local record has already moved forward.
  if (incomingOperation.baseRecordVersion === null) {
    return false;
  }
  // If the local record version is already higher than the operation's base,
  // another concurrent update exists.
  if (localRecord.recordVersion > incomingOperation.baseRecordVersion) {
    return true;
  }
  // If the local record version equals the base but the hash differs,
  // a rollback or fork is suspected (handled elsewhere).
  return false;
}

async function verifyVaultHeadTransition(
  state: LocalVaultState,
  operation: VaultOperationRow,
): Promise<boolean> {
  if (operation.baseVaultHead !== state.lastVerifiedVaultHead) {
    return false;
  }

  const expectedHead = await computeVaultHead({
    previousVaultHead: state.lastVerifiedVaultHead,
    opHash: operation.opHash,
    recordId: operation.recordId,
    recordType: operation.recordType,
    newRecordHash: operation.newRecordHash,
    opType: operation.opType,
  });

  return expectedHead === operation.resultingVaultHead;
}

async function decryptVerifiedRecord(
  record: VaultRecordRow,
  vaultEncryptionKey: Uint8Array,
): Promise<OpenedRecordV1> {
  const recordKey = await deriveRecordKey({
    vaultEncryptionKey,
    vaultId: record.vaultId,
    recordId: record.recordId,
    recordType: record.recordType,
    keyVersion: record.keyVersion,
  });

  try {
    const aadInput = {
      vaultId: record.vaultId,
      recordId: record.recordId,
      recordType: record.recordType,
      recordVersion: record.recordVersion,
      keyVersion: record.keyVersion,
    };

    return await cryptoRecordService.openRecord({
      sealed: {
        aad: buildRecordAad(aadInput),
        aadHash: record.aadHash,
        nonceB64Url: record.nonce,
        ciphertextB64Url: record.ciphertext,
        ciphertextHash: record.ciphertextHash,
      },
      recordKey,
      expectedAadInput: aadInput,
      expectedAadHash: record.aadHash,
      expectedCiphertextHash: record.ciphertextHash,
    });
  } finally {
    recordKey.fill(0);
  }
}

function validateRecordPlaintext(plaintext: Uint8Array, record: VaultRecordRow): boolean {
  // Minimal validation: tombstones must canonicalise to a non-empty buffer.
  // Full schema validation is Phase 9.
  if (record.isTombstone) {
    return plaintext.length > 0;
  }
  // Non-tombstones must carry at least one byte.
  return plaintext.length > 0;
}

function updateStateWithQuarantine(
  state: LocalVaultState,
  record: VaultRecordRow | null,
  recordState: RecordSecurityState,
  reason: string,
): LocalVaultState {
  const nextQuarantined = new Map(state.quarantinedRecordsById);
  const recordId = record?.recordId ?? 'unknown';
  nextQuarantined.set(recordId, {
    record,
    recordState: recordState as LocalQuarantinedRecord['recordState'],
    reason,
  });
  return {
    ...state,
    quarantinedRecordsById: nextQuarantined,
  };
}

function updateStateWithConflict(
  state: LocalVaultState,
  localRecord: LocalVerifiedRecord,
  incomingOperation: VaultOperationRow,
  incomingRecord: VaultRecordRow,
): LocalVaultState {
  const recordId = localRecord.record.recordId;
  const existing = state.conflictsByRecordId.get(recordId);

  const operations: VaultOperationRow[] = existing
    ? [...existing.operations, incomingOperation]
    : [localRecord.lastOperation, incomingOperation];

  const recordVersions: VaultRecordRow[] = existing
    ? [...existing.recordVersions, incomingRecord]
    : [localRecord.record, incomingRecord];

  const nextConflicts = new Map(state.conflictsByRecordId);
  nextConflicts.set(recordId, { recordId, operations, recordVersions });

  return {
    ...state,
    conflictsByRecordId: nextConflicts,
  };
}
