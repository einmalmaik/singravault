// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { syncPendingVaultOpLogOperations } from '../vaultOpLogPendingSyncService';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import type { PendingLocalOperation } from '../vaultOpLogPendingQueueTypes';
import type { VaultOperationRow, VaultRecordRow } from '../vaultOpLogRpcTypes';

const VAULT_ID = 'vault-pending-sync';
const STORAGE_KEY = `singra:vaultOpLog:pending:${VAULT_ID}`;

beforeEach(() => {
  localStorage.clear();
});

afterEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

describe('vaultOpLogPendingSyncService', () => {
  it('replays pending signed operations through submit_vault_operation and marks them synced', async () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([pendingEntry()]));
    const rpcClient = createRpcClient({
      applied: true,
      idempotent: false,
      op_id: 'op-1',
      sequence_number: 2,
      resulting_vault_head: 'head-server',
      current_head: 'head-server',
      current_sequence_number: 2,
      conflict_reason: null,
    });

    const result = await syncPendingVaultOpLogOperations({ rpcClient, vaultId: VAULT_ID });

    expect(result).toEqual({ processed: 1, remaining: 0, blocked: 0 });
    expect(rpcClient.rpc).toHaveBeenCalledWith(
      'submit_vault_operation',
      expect.objectContaining({
        p_op: expect.objectContaining({ op_id: 'op-1' }),
        p_record_payload: expect.objectContaining({ ciphertext_hash: 'ciphertext-hash-1' }),
      }),
    );
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]') as PendingLocalOperation[];
    expect(stored[0].state).toBe('synced');
    expect(stored[0].op.resultingVaultHead).toBe('head-server');
  });

  it('marks remote-head drift as rebase-needed instead of quarantining trusted local work', async () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([pendingEntry()]));
    const rpcClient = createRpcClient({
      applied: false,
      idempotent: false,
      op_id: 'op-1',
      sequence_number: null,
      resulting_vault_head: null,
      current_head: 'head-remote-newer',
      current_sequence_number: 10,
      conflict_reason: 'stale_vault_head',
    });

    const result = await syncPendingVaultOpLogOperations({ rpcClient, vaultId: VAULT_ID });

    expect(result).toEqual({ processed: 0, remaining: 1, blocked: 1 });
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]') as PendingLocalOperation[];
    expect(stored[0].state).toBe('rebase_needed');
  });
});

function createRpcClient(data: unknown): SupabaseRpcClient {
  return {
    rpc: vi.fn(async () => ({ data, error: null })),
  } as unknown as SupabaseRpcClient;
}

function pendingEntry(): PendingLocalOperation {
  return {
    op: operationRow(),
    record: recordRow(),
    createdAtLocal: '2026-05-12T00:00:00.000Z',
    retryCount: 0,
    lastError: null,
    state: 'pending',
  };
}

function operationRow(): VaultOperationRow {
  return {
    opId: 'op-1',
    opHash: 'op-hash-1',
    vaultId: VAULT_ID,
    authorDeviceId: 'device-1',
    opType: 'create',
    recordId: 'record-1',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'record-hash-1',
    baseVaultHead: 'head-0',
    resultingVaultHead: 'head-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'ciphertext-hash-1',
    payloadAadHash: 'aad-hash-1',
    signedBody: {},
    signature: 'signature-1',
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    trustEpoch: 0,
    createdAtClient: '2026-05-12T00:00:00.000Z',
    receivedAtServer: '',
    sequenceNumber: 0,
  };
}

function recordRow(): VaultRecordRow {
  return {
    vaultId: VAULT_ID,
    recordId: 'record-1',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
    aadHash: 'aad-hash-1',
    ciphertextHash: 'ciphertext-hash-1',
    nonce: 'nonce-1',
    ciphertext: 'sealed-ciphertext-1',
    lastOpId: 'op-1',
    lastOpHash: 'op-hash-1',
    isTombstone: false,
    createdAt: '2026-05-12T00:00:00.000Z',
    updatedAt: '2026-05-12T00:00:00.000Z',
  };
}
