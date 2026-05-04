// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the vault operation log rebase service (Phase 4).
 *
 * Coverage:
 * - Rebase produces a new op_id for the same intent_id.
 * - rebased_from_op_id points to the old op_id.
 * - New base_vault_head is set.
 * - New signing and new op_hash.
 * - Old record CAS valid -> rebased.
 * - Old record CAS stale -> conflict.
 * - Missing current record -> blocked.
 * - Operation not in rebase_needed state -> blocked.
 */

import { describe, expect, it } from 'vitest';
import { rebaseOperationWithPlaintext } from '../vaultOpLogRebaseService';
import { generateDeviceSigningKeyPair } from '../operationSigningService';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';
import type { PendingLocalOperation } from '../vaultOpLogPendingQueueTypes';
import type { VaultOperationRow } from '../vaultOpLogRpcTypes';

function makeOpRow(overrides?: Partial<VaultOperationRow>): VaultOperationRow {
  return {
    opId: 'op-old',
    opHash: 'hash-old',
    vaultId: 'v1',
    authorDeviceId: 'dev-1',
    opType: 'update',
    recordId: 'rec-1',
    recordType: 'item',
    baseRecordVersion: 2,
    previousCiphertextHash: 'prev-ct',
    newRecordHash: 'nrh',
    baseVaultHead: 'head-old',
    resultingVaultHead: 'rvh-old',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'pct',
    payloadAadHash: 'pah',
    signedBody: {},
    signature: 'sig-old',
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    trustEpoch: 0,
    createdAtClient: '2026-05-01T00:00:00.000Z',
    receivedAtServer: '',
    sequenceNumber: 0,
    ...overrides,
  };
}

function makePending(state: 'pending' | 'rebase_needed' | 'conflict' = 'rebase_needed'): PendingLocalOperation {
  return {
    op: makeOpRow(),
    record: {
      vaultId: 'v1',
      recordId: 'rec-1',
      recordType: 'item',
      recordVersion: 2,
      keyVersion: 1,
      aadHash: 'aad',
      ciphertextHash: 'prev-ct',
      nonce: 'n',
      ciphertext: 'c',
      lastOpId: 'op-old',
      lastOpHash: 'hash-old',
      isTombstone: false,
      createdAt: '2026-05-01T00:00:00.000Z',
      updatedAt: '2026-05-01T00:00:00.000Z',
    },
    createdAtLocal: '2026-05-01T00:00:00.000Z',
    retryCount: 0,
    lastError: null,
    state,
  };
}

describe('rebaseOperationWithPlaintext', () => {
  it('returns conflict when previous_ciphertext_hash is stale', async () => {
    const { privateKey } = await generateDeviceSigningKeyPair();
    const result = await rebaseOperationWithPlaintext(
      makePending(),
      new TextEncoder().encode('updated'),
      {
        currentVaultHead: 'head-new',
        currentRecord: { recordVersion: 3, ciphertextHash: 'different-ct' },
        deviceSigningKey: privateKey,
        vaultEncryptionKey: crypto.getRandomValues(new Uint8Array(32)),
      },
    );
    expect(result.kind).toBe('conflict');
  });

  it('returns blocked when currentRecord is null', async () => {
    const { privateKey } = await generateDeviceSigningKeyPair();
    const result = await rebaseOperationWithPlaintext(
      makePending(),
      new TextEncoder().encode('updated'),
      {
        currentVaultHead: 'head-new',
        currentRecord: null,
        deviceSigningKey: privateKey,
        vaultEncryptionKey: crypto.getRandomValues(new Uint8Array(32)),
      },
    );
    expect(result.kind).toBe('blocked');
  });

  it('returns blocked when state is not rebase_needed', async () => {
    const { privateKey } = await generateDeviceSigningKeyPair();
    const result = await rebaseOperationWithPlaintext(
      makePending('pending'),
      new TextEncoder().encode('updated'),
      {
        currentVaultHead: 'head-new',
        currentRecord: { recordVersion: 2, ciphertextHash: 'prev-ct' },
        deviceSigningKey: privateKey,
        vaultEncryptionKey: crypto.getRandomValues(new Uint8Array(32)),
      },
    );
    expect(result.kind).toBe('blocked');
  });

  it('produces a rebased operation with new op_id and same intent_id', async () => {
    const { privateKey } = await generateDeviceSigningKeyPair();
    const vaultEncKey = crypto.getRandomValues(new Uint8Array(32));
    const oldPending = makePending();

    const result = await rebaseOperationWithPlaintext(
      oldPending,
      new TextEncoder().encode('updated'),
      {
        currentVaultHead: 'head-new',
        currentRecord: { recordVersion: 2, ciphertextHash: 'prev-ct' },
        deviceSigningKey: privateKey,
        vaultEncryptionKey: vaultEncKey,
      },
    );

    expect(result.kind).toBe('rebased');
    if (result.kind === 'rebased') {
      expect(result.oldOpId).toBe('op-old');
      expect(result.newPending.op.opId).not.toBe('op-old');
      expect(result.newPending.op.intentId).toBe('intent-1');
      expect(result.newPending.op.rebasedFromOpId).toBe('op-old');
      expect(result.newPending.op.baseVaultHead).toBe('head-new');
      expect(result.newPending.op.baseRecordVersion).toBe(2);
      expect(result.newPending.op.previousCiphertextHash).toBe('prev-ct');
      expect(result.newPending.state).toBe('pending');
      expect(result.newPending.op.signature).not.toBe('sig-old');
      expect(result.newPending.op.opHash).not.toBe('hash-old');
      expect(result.newPending.record?.recordType).toBe('item');
    }
  });

  it('rebase increments baseRecordVersion to current+1', async () => {
    const { privateKey } = await generateDeviceSigningKeyPair();
    const vaultEncKey = crypto.getRandomValues(new Uint8Array(32));

    const result = await rebaseOperationWithPlaintext(
      makePending(),
      new TextEncoder().encode('updated'),
      {
        currentVaultHead: 'head-new',
        currentRecord: { recordVersion: 5, ciphertextHash: 'prev-ct' },
        deviceSigningKey: privateKey,
        vaultEncryptionKey: vaultEncKey,
      },
    );

    expect(result.kind).toBe('rebased');
    if (result.kind === 'rebased') {
      expect(result.newPending.op.baseRecordVersion).toBe(5);
      expect(result.newPending.record?.recordVersion).toBe(6);
    }
  });
});
