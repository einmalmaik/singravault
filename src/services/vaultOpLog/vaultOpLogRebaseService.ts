// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Rebase service for the vault operation log (Phase 4).
 *
 * When a pending operation is rejected with stale base_vault_head,
 * the rebase workflow creates a *new* operation (new op_id, new
 * signature, new op_hash) for the *same user intent* (same
 * intent_id). The old queue entry is marked superseded. The new
 * entry is pending.
 *
 * If the record CAS (previous_ciphertext_hash) is no longer valid,
 * the operation becomes a conflict instead — no automatic rebase,
 * no last-write-wins.
 */

import { randomUuid } from '@dis/shield/random';
import { canonicalizeVaultStructure } from './canonicalJson';
import { deriveRecordKey, sealRecord } from './cryptoRecordService';
import { buildOperationSignedBody, signOperation } from './operationSigningService';
import { computeVaultHead } from './recordHashes';
import { isRecordType } from './types';
import { toVaultOperationRow, toVaultRecordRow } from './vaultOpLogOperationBuilder';
import type { PendingLocalOperation } from './vaultOpLogPendingQueueTypes';
import type { VaultOperationRow, VaultRecordRow } from './vaultOpLogRpcTypes';

export interface RebaseContext {
  readonly currentVaultHead: string;
  readonly currentRecord: { readonly recordVersion: number; readonly ciphertextHash: string } | null;
  readonly deviceSigningKey: CryptoKey;
  readonly vaultEncryptionKey: Uint8Array;
}

export type RebaseResult =
  | { readonly kind: 'rebased'; readonly newPending: PendingLocalOperation; readonly oldOpId: string }
  | { readonly kind: 'conflict'; readonly reason: string }
  | { readonly kind: 'blocked'; readonly reason: string };

/**
 * Attempt to rebase a pending operation. Requires the plaintext bytes
 * because the queue only stores sealed records, not plaintext.
 */
export async function rebaseOperationWithPlaintext(
  oldPending: PendingLocalOperation,
  plaintext: Uint8Array,
  context: RebaseContext,
): Promise<RebaseResult> {
  if (oldPending.state !== 'rebase_needed') {
    return { kind: 'blocked', reason: 'operation state is not rebase_needed' };
  }

  const op = oldPending.op;
  const record = oldPending.record;

  if (context.currentRecord === null) {
    return { kind: 'blocked', reason: 'affected record missing from current vault state' };
  }

  if (op.previousCiphertextHash !== context.currentRecord.ciphertextHash) {
    return {
      kind: 'conflict',
      reason: 'previous_ciphertext_hash stale: record was modified by another device',
    };
  }

  const newOpId = randomUuid();
  const createdAtClient = new Date().toISOString();
  const nextRecordVersion = context.currentRecord.recordVersion + 1;
  const isTombstone = op.opType === 'delete';
  const recordType = isTombstone ? 'tombstone' : op.recordType;
  const opRecordType = op.recordType;

  if (!isRecordType(recordType) || !isRecordType(opRecordType)) {
    return { kind: 'blocked', reason: 'invalid recordType in pending operation' };
  }

  const payloadPlaintext = isTombstone
    ? canonicalizeVaultStructure({ tombstone: true, deletedAt: createdAtClient })
    : plaintext;

  const keyVersion = record?.keyVersion ?? 1;
  const recordKey = await deriveRecordKey({
    vaultEncryptionKey: context.vaultEncryptionKey,
    vaultId: op.vaultId,
    recordId: op.recordId,
    recordType,
    keyVersion,
  });

  let sealed;
  try {
    sealed = await sealRecord({
      plaintext: payloadPlaintext,
      recordKey,
      aadInput: {
        vaultId: op.vaultId,
        recordId: op.recordId,
        recordType,
        recordVersion: nextRecordVersion,
        keyVersion,
      },
    });
  } finally {
    recordKey.fill(0);
  }

  const body = buildOperationSignedBody({
    opId: newOpId,
    intentId: op.intentId ?? newOpId,
    rebasedFromOpId: op.opId,
    vaultId: op.vaultId,
    authorDeviceId: op.authorDeviceId,
    opType: op.opType,
    recordId: op.recordId,
    recordType: opRecordType,
    baseRecordVersion: context.currentRecord.recordVersion,
    previousCiphertextHash: context.currentRecord.ciphertextHash,
    newRecordHash: sealed.ciphertextHash,
    baseVaultHead: context.currentVaultHead,
    payloadCiphertextHash: sealed.ciphertextHash,
    payloadAadHash: sealed.aadHash,
    createdAtClient,
    trustEpoch: op.trustEpoch,
  });

  const signed = await signOperation(body, context.deviceSigningKey);

  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: context.currentVaultHead,
    opHash: signed.opHash,
    recordId: op.recordId,
    recordType: opRecordType,
    newRecordHash: sealed.ciphertextHash,
    opType: op.opType,
  });

  const opRow: VaultOperationRow = {
    ...toVaultOperationRow({ signedOperation: signed, resultingVaultHead, sealedRecord: sealed }),
    authorDeviceId: op.authorDeviceId,
    trustEpoch: op.trustEpoch,
  };

  const recRow: VaultRecordRow = toVaultRecordRow(sealed, opRow, isTombstone);

  const newPending: PendingLocalOperation = {
    op: opRow,
    record: recRow,
    createdAtLocal: createdAtClient,
    retryCount: 0,
    lastError: null,
    state: 'pending',
  };

  return { kind: 'rebased', newPending, oldOpId: op.opId };
}
