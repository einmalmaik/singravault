// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the local pending operation queue (Phase 4).
 *
 * Coverage:
 * - Enqueue creates a pending entry.
 * - State transitions: pending -> syncing -> synced.
 * - Retry increments retryCount and keeps op_id/intent_id stable.
 * - Rebase needed classification.
 * - Conflict classification.
 * - Crash recovery: syncing -> pending.
 * - Sanitized lastError contains no secrets.
 * - Idempotent success classification.
 * - Permanent failure on duplicate op_id + different hash.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import {
  VaultOpLogPendingQueue,
  classifySubmitResult,
  sanitizeQueueErrorForStorage,
} from '../vaultOpLogPendingQueue';
import { InMemoryQueuePersistence } from '../vaultOpLogQueuePersistence';
import type { PendingLocalOperation } from '../vaultOpLogPendingQueueTypes';
import type { VaultOperationRow, SubmitVaultOperationResult } from '../vaultOpLogRpcTypes';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';

function makeOpRow(overrides?: Partial<VaultOperationRow>): VaultOperationRow {
  return {
    opId: 'op-1',
    opHash: 'hash-1',
    vaultId: 'v1',
    authorDeviceId: 'dev-1',
    opType: 'create',
    recordId: 'rec-1',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'nrh',
    baseVaultHead: null,
    resultingVaultHead: 'rvh',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'pct',
    payloadAadHash: 'pah',
    signedBody: {},
    signature: 'sig',
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    trustEpoch: 0,
    createdAtClient: '2026-05-01T00:00:00.000Z',
    receivedAtServer: '',
    sequenceNumber: 0,
    ...overrides,
  };
}

function makePendingEntry(overrides?: Partial<PendingLocalOperation>): PendingLocalOperation {
  return {
    op: makeOpRow(),
    record: null,
    createdAtLocal: '2026-05-01T00:00:00.000Z',
    retryCount: 0,
    lastError: null,
    state: 'pending',
    ...overrides,
  };
}

let persistence: InMemoryQueuePersistence;

beforeEach(() => {
  persistence = new InMemoryQueuePersistence();
});

describe('VaultOpLogPendingQueue', () => {
  it('initially has no operations', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    expect(q.getOperations().length).toBe(0);
  });

  it('enqueue adds a pending operation', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();

    const built = {
      signedOperation: {
        body: makeOpRow(),
        signature: 'sig',
        opHash: 'hash-1',
      } as unknown,
      resultingVaultHead: 'rvh',
      sealedRecord: {
        aadHash: 'aad',
        ciphertextHash: 'ct',
        nonceB64Url: 'n',
        ciphertextB64Url: 'c',
        aad: { recordType: 'item', vaultId: 'v1', recordId: 'rec-1', recordVersion: 1, keyVersion: 1, app: 'singra', aadSchema: 'record-aad-v1' },
      } as unknown,
    };

    await q.enqueue(built as unknown as import('../vaultOpLogOperationBuilder').BuiltVaultOperation);
    expect(q.getPending().length).toBe(1);
    expect(q.getPending()[0].record?.isTombstone).toBe(false);
    expect(q.getPending()[0].state).toBe('pending');
  });

  it('marks syncing then synced', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    q['operations'] = [makePendingEntry()];

    await q.markSyncing('op-1');
    expect(q.getSyncing().length).toBe(1);

    await q.markSynced('op-1', 'new-head');
    const synced = q.getOperations().filter((e) => e.state === 'synced');
    expect(synced.length).toBe(1);
    expect(synced[0].op.resultingVaultHead).toBe('new-head');
  });

  it('retry increments retryCount and keeps op_id stable', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    q['operations'] = [makePendingEntry()];

    await q.markRetryable('op-1', 'network timeout');
    const pending = q.getPending();
    expect(pending.length).toBe(1);
    expect(pending[0].retryCount).toBe(1);
    expect(pending[0].lastError).toBe('network timeout');
    expect(pending[0].op.opId).toBe('op-1');
    expect(pending[0].op.intentId).toBe('intent-1');
  });

  it('marks rebase_needed', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    q['operations'] = [makePendingEntry()];

    await q.markRebaseNeeded('op-1');
    expect(q.getRebaseNeeded().length).toBe(1);
  });

  it('marks conflict', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    q['operations'] = [makePendingEntry()];

    await q.markConflict('op-1', 'stale ciphertext hash');
    const conflicts = q.getOperations().filter((e) => e.state === 'conflict');
    expect(conflicts.length).toBe(1);
  });

  it('recoverAfterCrash rolls syncing back to pending', async () => {
    const q = new VaultOpLogPendingQueue('v1', persistence);
    await q.load();
    q['operations'] = [
      makePendingEntry({ state: 'syncing', retryCount: 0 }),
      makePendingEntry({ op: makeOpRow({ opId: 'op-2' }), state: 'pending' }),
    ];

    await q.recoverAfterCrash();
    const all = q.getOperations();
    expect(all[0].state).toBe('pending');
    expect(all[0].retryCount).toBe(1);
    expect(all[0].lastError).toContain('recovered_from_crash');
    expect(all[1].state).toBe('pending');
  });

  it('persists across load/save cycles', async () => {
    const q1 = new VaultOpLogPendingQueue('v1', persistence);
    await q1.load();
    q1['operations'] = [makePendingEntry()];
    await q1.save();

    const q2 = new VaultOpLogPendingQueue('v1', persistence);
    await q2.load();
    expect(q2.getOperations().length).toBe(1);
  });
});

describe('classifySubmitResult', () => {
  it('classifies applied as synced', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'applied',
      idempotent: false,
      opId: 'op-1',
      sequenceNumber: 1,
      resultingVaultHead: 'rvh',
      currentHead: 'ch',
      currentSequenceNumber: 1,
    };
    const classified = classifySubmitResult(result);
    expect(classified.kind).toBe('synced');
    if (classified.kind === 'synced') {
      expect(classified.resultingVaultHead).toBe('rvh');
    }
  });

  it('classifies idempotent applied as idempotentSynced', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'applied',
      idempotent: true,
      opId: 'op-1',
      sequenceNumber: 1,
      resultingVaultHead: 'rvh',
      currentHead: 'ch',
      currentSequenceNumber: 1,
    };
    const classified = classifySubmitResult(result);
    expect(classified.kind).toBe('idempotentSynced');
  });

  it('classifies rebaseNeeded', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'rebaseNeeded',
      currentHead: 'ch',
      currentSequenceNumber: 2,
    };
    expect(classifySubmitResult(result).kind).toBe('rebaseNeeded');
  });

  it('classifies recordConflictStaleCiphertextHash as conflict', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'recordConflictStaleCiphertextHash',
      currentRecordVersion: 3,
      currentHead: 'ch',
      currentSequenceNumber: 2,
    };
    expect(classifySubmitResult(result).kind).toBe('recordConflict');
  });

  it('classifies duplicateOpIdDifferentHash as permanentFailed', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'duplicateOpIdDifferentHash',
    };
    expect(classifySubmitResult(result).kind).toBe('permanentFailed');
  });

  it('classifies unauthorized as permanentFailed', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'unauthorized',
    };
    expect(classifySubmitResult(result).kind).toBe('permanentFailed');
  });

  it('classifies vaultOwnershipError as permanentFailed', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'vaultOwnershipError',
    };
    expect(classifySubmitResult(result).kind).toBe('permanentFailed');
  });

  it('classifies rpcError as retryable', () => {
    const result: SubmitVaultOperationResult = {
      kind: 'rpcError',
      code: 'P0001',
      message: 'transient',
    };
    expect(classifySubmitResult(result).kind).toBe('retryable');
  });
});

describe('sanitizeQueueErrorForStorage', () => {
  it('strips long base64-like strings that could be ciphertext', () => {
    const dirty = 'failed with ciphertext ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
    const clean = sanitizeQueueErrorForStorage(dirty);
    expect(clean).not.toContain('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-');
    expect(clean).toContain('<redacted>');
  });

  it('truncates very long errors', () => {
    const dirty = 'error '.repeat(300); // spaces prevent base64 redaction
    const clean = sanitizeQueueErrorForStorage(dirty);
    expect(clean.length).toBeLessThan(600);
    expect(clean).toContain('<truncated>');
  });
});
