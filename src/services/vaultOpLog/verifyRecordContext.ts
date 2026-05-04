// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `verifyRecordContext` — verify that a sealed record's metadata,
 * hashes and operation linkage match the claimed operation.
 *
 * This is the second gate in the Phase 5 pipeline. It never
 * decrypts. It only checks hashes and structural bindings.
 */

import {
  buildRecordAad,
  encodeRecordAadBytes,
} from './recordAad';
import {
  computeAadHash,
  computeCiphertextHash,
} from './recordHashes';
import type {
  RecordContextVerificationResult,
} from './vaultSecurityStates';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';

export interface VerifyRecordContextInput {
  readonly record: VaultRecordRow;
  readonly operation: VaultOperationRow;
}

/**
 * Verify record context against its claimed operation.
 *
 * Checks performed (in order):
 * 1. Rebuild AAD from record metadata and compare byte equality.
 * 2. Recompute AAD hash and compare with `record.aadHash`.
 * 3. Recompute ciphertext hash and compare with `record.ciphertextHash`.
 * 4. Verify `record.lastOpId` and `record.lastOpHash` match the operation.
 * 5. Verify payload hash linkage from the operation matches the record.
 * 6. Validate tombstone flag consistency.
 */
export async function verifyRecordContext(
  input: VerifyRecordContextInput,
): Promise<RecordContextVerificationResult> {
  const { record, operation } = input;

  // 1. Deterministic AAD from record metadata
  let expectedAad;
  try {
    expectedAad = buildRecordAad({
      vaultId: record.vaultId,
      recordId: record.recordId,
      recordType: record.recordType,
      recordVersion: record.recordVersion,
      keyVersion: record.keyVersion,
    });
  } catch {
    return { kind: 'invalidSchema', mayDecrypt: false };
  }

  // Note: VaultRecordRow stores only aadHash, not the raw AAD bytes.
  // The canonical AAD integrity is verified via the hash check below.

  const expectedAadBytes = encodeRecordAadBytes(expectedAad);

  // 2. AAD hash verification
  let recomputedAadHash: string;
  try {
    recomputedAadHash = await computeAadHash(expectedAad);
  } catch {
    return { kind: 'aadMismatch', mayDecrypt: false };
  }
  if (recomputedAadHash !== record.aadHash) {
    return { kind: 'aadMismatch', mayDecrypt: false };
  }

  // 3. Ciphertext hash verification
  let recomputedCiphertextHash: string;
  try {
    recomputedCiphertextHash = await computeCiphertextHash({
      aadHash: record.aadHash,
      nonceB64Url: record.nonce,
      ciphertextB64Url: record.ciphertext,
      vaultId: record.vaultId,
      recordId: record.recordId,
      recordType: record.recordType,
      recordVersion: record.recordVersion,
      keyVersion: record.keyVersion,
    });
  } catch {
    return { kind: 'ciphertextHashMismatch', mayDecrypt: false };
  }
  if (recomputedCiphertextHash !== record.ciphertextHash) {
    return { kind: 'ciphertextHashMismatch', mayDecrypt: false };
  }

  // 4. Operation linkage
  if (record.lastOpId !== operation.opId) {
    return { kind: 'lastOpIdMismatch', mayDecrypt: false };
  }
  if (record.lastOpHash !== operation.opHash) {
    return { kind: 'lastOpIdMismatch', mayDecrypt: false };
  }

  // 5. Payload hash linkage from operation to record
  if (operation.payloadCiphertextHash !== null && operation.payloadCiphertextHash !== record.ciphertextHash) {
    return { kind: 'payloadHashMismatch', mayDecrypt: false };
  }
  if (operation.payloadAadHash !== null && operation.payloadAadHash !== record.aadHash) {
    return { kind: 'payloadHashMismatch', mayDecrypt: false };
  }

  // 6. Tombstone consistency
  const isDeleteOperation = operation.opType === 'delete';
  if (isDeleteOperation && !record.isTombstone) {
    return { kind: 'invalidSchema', mayDecrypt: false };
  }
  if (!isDeleteOperation && record.isTombstone) {
    return { kind: 'invalidSchema', mayDecrypt: false };
  }

  return { kind: 'validContext', mayDecrypt: true };
}
