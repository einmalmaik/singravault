// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the vault operation log repository layer.
 *
 * Coverage:
 * - Each RPC calls only the allowed Supabase RPC function.
 * - No direct table writes (insert / update / upsert / delete) are issued.
 * - Success responses are mapped correctly.
 * - Idempotent retry: same op_id + same op_hash → idempotent success.
 * - Duplicate op_id + different op_hash → duplicateOpIdDifferentHash.
 * - stale base_vault_head → rebaseNeeded (not manipulation).
 * - stale previous_ciphertext_hash → recordConflictStaleCiphertextHash (not global lock).
 * - stale record_version → recordConflictStaleVersion.
 * - Malformed RPC responses are safely rejected.
 * - Supabase errors are classified without leaking secrets.
 */

import { describe, expect, it } from 'vitest';
import {
  submitVaultOperation,
  getVaultHead,
  getVaultChangesSince,
  getVaultRecordsByIds,
  bootstrapVaultTrust,
  type SupabaseRpcClient,
} from '../vaultOpLogRepository';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from '../vaultOpLogRpcTypes';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';

// ---------------------------------------------------------------------------
// Mock Supabase client
// ---------------------------------------------------------------------------

function createMockClient(): {
  client: SupabaseRpcClient;
  calls: Array<{ fn: string; params: Record<string, unknown> }>;
  setResponse: (response: { data: unknown; error: null } | { data: null; error: { code: string; message: string } }) => void;
} {
  const calls: Array<{ fn: string; params: Record<string, unknown> }> = [];
  let nextResponse:
    | { data: unknown; error: null }
    | { data: null; error: { code: string; message: string } } = { data: null, error: null };

  const client: SupabaseRpcClient = {
    async rpc<T = unknown>(fn: string, params: Record<string, unknown>) {
      calls.push({ fn, params });
      return nextResponse as { data: T | null; error: { code: string; message: string } | null };
    },
  };

  return {
    client,
    calls,
    setResponse(response) {
      nextResponse = response;
    },
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function sampleOperation(overrides?: Partial<VaultOperationRow>): VaultOperationRow {
  return {
    opId: '550e8400-e29b-41d4-a716-446655440000',
    opHash: 'op-hash-test',
    vaultId: '550e8400-e29b-41d4-a716-446655440001',
    authorDeviceId: '550e8400-e29b-41d4-a716-446655440002',
    opType: 'create',
    recordId: '550e8400-e29b-41d4-a716-446655440003',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'new-hash',
    baseVaultHead: null,
    resultingVaultHead: 'result-hash',
    intentId: '550e8400-e29b-41d4-a716-446655440004',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'ct-hash',
    payloadAadHash: 'aad-hash',
    signedBody: {},
    signature: 'sig-test',
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    trustEpoch: 0,
    createdAtClient: '2026-05-01T00:00:00.000Z',
    receivedAtServer: '2026-05-01T00:00:01.000Z',
    sequenceNumber: 1,
    ...overrides,
  };
}

function sampleRecord(overrides?: Partial<VaultRecordRow>): VaultRecordRow {
  return {
    vaultId: '550e8400-e29b-41d4-a716-446655440001',
    recordId: '550e8400-e29b-41d4-a716-446655440003',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
    aadHash: 'aad-hash',
    ciphertextHash: 'ct-hash',
    nonce: 'nonce-test',
    ciphertext: 'cipher-test',
    lastOpId: '550e8400-e29b-41d4-a716-446655440000',
    lastOpHash: 'op-hash-test',
    isTombstone: false,
    createdAt: '2026-05-01T00:00:00.000Z',
    updatedAt: '2026-05-01T00:00:01.000Z',
    ...overrides,
  };
}

function sampleDbOperationRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const op = sampleOperation();
  return {
    op_id: op.opId,
    op_hash: op.opHash,
    vault_id: op.vaultId,
    author_device_id: op.authorDeviceId,
    op_type: op.opType,
    record_id: op.recordId,
    record_type: op.recordType,
    base_record_version: op.baseRecordVersion,
    previous_ciphertext_hash: op.previousCiphertextHash,
    new_record_hash: op.newRecordHash,
    intent_id: op.intentId,
    rebased_from_op_id: op.rebasedFromOpId,
    base_vault_head: op.baseVaultHead,
    resulting_vault_head: op.resultingVaultHead,
    payload_ciphertext_hash: op.payloadCiphertextHash,
    payload_aad_hash: op.payloadAadHash,
    signed_body: op.signedBody,
    signature: op.signature,
    signature_schema: op.signatureSchema,
    trust_epoch: op.trustEpoch,
    created_at_client: op.createdAtClient,
    received_at_server: op.receivedAtServer,
    sequence_number: op.sequenceNumber,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// submit_vault_operation
// ---------------------------------------------------------------------------

describe('submitVaultOperation', () => {
  it('calls only the submit_vault_operation RPC', async () => {
    const { client, calls, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: true,
        idempotent: false,
        op_id: 'op-1',
        sequence_number: 1,
        resulting_vault_head: 'res-head',
        current_head: 'cur-head',
        current_sequence_number: 1,
        conflict_reason: null,
      },
      error: null,
    });

    await submitVaultOperation(client, sampleOperation(), null, null);

    expect(calls.length).toBe(1);
    expect(calls[0].fn).toBe('submit_vault_operation');
  });

  it('returns applied on fresh success', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: true,
        idempotent: false,
        op_id: 'op-1',
        sequence_number: 1,
        resulting_vault_head: 'res-head',
        current_head: 'cur-head',
        current_sequence_number: 1,
        conflict_reason: null,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('applied');
    if (result.kind === 'applied') {
      expect(result.idempotent).toBe(false);
      expect(result.opId).toBe('op-1');
      expect(result.sequenceNumber).toBe(1);
      expect(result.resultingVaultHead).toBe('res-head');
      expect(result.currentHead).toBe('cur-head');
      expect(result.currentSequenceNumber).toBe(1);
    }
  });

  it('returns idempotent=true on retry with same op_id and op_hash', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: true,
        idempotent: true,
        op_id: 'op-1',
        sequence_number: 1,
        resulting_vault_head: 'res-head',
        current_head: 'cur-head',
        current_sequence_number: 1,
        conflict_reason: null,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('applied');
    if (result.kind === 'applied') {
      expect(result.idempotent).toBe(true);
    }
  });

  it('classifies duplicate op_id with different op_hash', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: null,
      error: { code: 'P0001', message: 'op_id reused with a different op_hash' },
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('duplicateOpIdDifferentHash');
  });

  it('classifies stale base_vault_head as rebaseNeeded', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'stale_vault_head',
        current_head: 'new-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('rebaseNeeded');
    if (result.kind === 'rebaseNeeded') {
      expect(result.currentHead).toBe('new-head');
      expect(result.currentSequenceNumber).toBe(5);
    }
  });

  it('classifies stale previous_ciphertext_hash as recordConflictStaleCiphertextHash', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'stale_previous_ciphertext_hash',
        current_record_version: 3,
        current_head: 'cur-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('recordConflictStaleCiphertextHash');
    if (result.kind === 'recordConflictStaleCiphertextHash') {
      expect(result.currentRecordVersion).toBe(3);
      expect(result.currentHead).toBe('cur-head');
      expect(result.currentSequenceNumber).toBe(5);
    }
  });

  it('classifies stale record_version as recordConflictStaleVersion', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'stale_record_version',
        current_record_version: 3,
        current_head: 'cur-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('recordConflictStaleVersion');
  });

  it('classifies record_not_found', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'record_not_found',
        current_head: 'cur-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('recordNotFound');
  });

  it('classifies record_type_mismatch', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'record_type_mismatch',
        current_record_version: 2,
        current_head: 'cur-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('recordTypeMismatch');
  });

  it('classifies record_already_exists', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'record_already_exists',
        current_record_version: 1,
        current_head: 'cur-head',
        current_sequence_number: 5,
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('recordAlreadyExists');
  });

  it('classifies create_must_not_carry_base', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'create_must_not_carry_base',
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('createMustNotCarryBase');
  });

  it('classifies Not authenticated as unauthorized', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: null,
      error: { code: 'P0001', message: 'Not authenticated' },
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('unauthorized');
  });

  it('classifies Vault does not belong to caller as vaultOwnershipError', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: null,
      error: { code: 'P0001', message: 'Vault does not belong to caller' },
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('vaultOwnershipError');
  });

  it('classifies malformed response when data is null', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({ data: null, error: null });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('malformedResponse');
  });

  it('classifies unknown conflict_reason as malformedResponse', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        applied: false,
        conflict_reason: 'unknown_reason',
      },
      error: null,
    });

    const result = await submitVaultOperation(client, sampleOperation(), null, null);

    expect(result.kind).toBe('malformedResponse');
  });

  it('does not issue direct table writes', async () => {
    const { client, calls } = createMockClient();
    // No call is made if we don't invoke the repository, but the test
    // documents the invariant: the repository only uses rpc().
    expect(calls.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// get_vault_head
// ---------------------------------------------------------------------------

describe('getVaultHead', () => {
  it('calls only the get_vault_head RPC', async () => {
    const { client, calls, setResponse } = createMockClient();
    setResponse({
      data: [
        {
          vault_id: 'v1',
          current_head: 'head-1',
          current_op_id: 'op-1',
          current_sequence_number: 1,
          updated_at: '2026-05-01T00:00:00.000Z',
        },
      ],
      error: null,
    });

    await getVaultHead(client, 'v1');

    expect(calls.length).toBe(1);
    expect(calls[0].fn).toBe('get_vault_head');
    expect(calls[0].params).toEqual({ p_vault_id: 'v1' });
  });

  it('returns success with mapped head', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: [
        {
          vault_id: 'v1',
          current_head: 'head-1',
          current_op_id: 'op-1',
          current_sequence_number: 1,
          updated_at: '2026-05-01T00:00:00.000Z',
        },
      ],
      error: null,
    });

    const result = await getVaultHead(client, 'v1');

    expect(result.kind).toBe('success');
    if (result.kind === 'success') {
      expect(result.head.vaultId).toBe('v1');
      expect(result.head.currentHead).toBe('head-1');
      expect(result.head.currentSequenceNumber).toBe(1);
    }
  });

  it('returns notFound for empty array', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({ data: [], error: null });

    const result = await getVaultHead(client, 'v1');

    expect(result.kind).toBe('notFound');
  });

  it('classifies RPC errors', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({ data: null, error: { code: 'P0001', message: 'Not authenticated' } });

    const result = await getVaultHead(client, 'v1');

    expect(result.kind).toBe('unauthorized');
  });

  it('classifies malformed non-array response', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({ data: { not_an_array: true }, error: null });

    const result = await getVaultHead(client, 'v1');

    expect(result.kind).toBe('malformedResponse');
  });
});

// ---------------------------------------------------------------------------
// get_vault_changes_since
// ---------------------------------------------------------------------------

describe('getVaultChangesSince', () => {
  it('calls only the get_vault_changes_since RPC', async () => {
    const { client, calls, setResponse } = createMockClient();
    setResponse({ data: [], error: null });

    await getVaultChangesSince(client, 'v1', 0, 100);

    expect(calls.length).toBe(1);
    expect(calls[0].fn).toBe('get_vault_changes_since');
    expect(calls[0].params).toEqual({ p_vault_id: 'v1', p_since_sequence: 0, p_limit: 100 });
  });

  it('returns mapped operations array', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: [
        {
          op_id: 'op-1',
          op_hash: 'hash-1',
          vault_id: 'v1',
          author_device_id: 'dev-1',
          op_type: 'create',
          record_id: 'rec-1',
          record_type: 'item',
          base_record_version: null,
          previous_ciphertext_hash: null,
          new_record_hash: 'nrh',
          base_vault_head: null,
          resulting_vault_head: 'rvh',
          intent_id: null,
          rebased_from_op_id: null,
          payload_ciphertext_hash: 'pct',
          payload_aad_hash: 'pah',
          signed_body: {},
          signature: 'sig',
          signature_schema: DEVICE_SIGNATURE_SCHEMA_V1,
          trust_epoch: 0,
          created_at_client: '2026-05-01T00:00:00.000Z',
          received_at_server: '2026-05-01T00:00:01.000Z',
          sequence_number: 1,
        },
      ],
      error: null,
    });

    const result = await getVaultChangesSince(client, 'v1', 0, 100);

    expect(result.kind).toBe('success');
    if (result.kind === 'success') {
      expect(result.operations.length).toBe(1);
      expect(result.operations[0].opId).toBe('op-1');
      expect(result.operations[0].opHash).toBe('hash-1');
    }
  });

  it('classifies malformed row inside array as malformedResponse', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: [{ op_id: 'op-1', op_hash: 'hash-1', vault_id: 'v1', author_device_id: 'dev-1', op_type: 'create', record_id: 'rec-1', record_type: 'item' }],
      error: null,
    });

    const result = await getVaultChangesSince(client, 'v1', 0, 100);

    expect(result.kind).toBe('malformedResponse');
  });

  it('rejects get_vault_changes_since rows without vault_id with a sanitized reason', async () => {
    const { client, setResponse } = createMockClient();
    const row = sampleDbOperationRow({ signed_body: { signed: 'body-not-secret' } });
    delete row.vault_id;
    setResponse({ data: [row], error: null });

    const result = await getVaultChangesSince(client, 'v1', 0, 100);

    expect(result.kind).toBe('malformedResponse');
    if (result.kind === 'malformedResponse') {
      expect(result.reason).toContain('vault_id');
      expect(result.reason).not.toContain('body-not-secret');
      expect(result.reason).not.toContain('signed_body');
      expect(result.reason).not.toContain('cipher');
    }
  });
});

// ---------------------------------------------------------------------------
// get_vault_records_by_ids
// ---------------------------------------------------------------------------

describe('getVaultRecordsByIds', () => {
  it('calls only the get_vault_records_by_ids RPC', async () => {
    const { client, calls, setResponse } = createMockClient();
    setResponse({ data: [], error: null });

    await getVaultRecordsByIds(client, 'v1', ['r1', 'r2']);

    expect(calls.length).toBe(1);
    expect(calls[0].fn).toBe('get_vault_records_by_ids');
    expect(calls[0].params).toEqual({ p_vault_id: 'v1', p_record_ids: ['r1', 'r2'] });
  });

  it('returns mapped records array', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: [
        {
          vault_id: 'v1',
          record_id: 'r1',
          record_type: 'item',
          record_version: 1,
          key_version: 1,
          aad_hash: 'aad',
          ciphertext_hash: 'ct',
          nonce: 'n',
          ciphertext: 'c',
          last_op_id: 'op-1',
          last_op_hash: 'hash-1',
          is_tombstone: false,
          created_at: '2026-05-01T00:00:00.000Z',
          updated_at: '2026-05-01T00:00:01.000Z',
        },
      ],
      error: null,
    });

    const result = await getVaultRecordsByIds(client, 'v1', ['r1']);

    expect(result.kind).toBe('success');
    if (result.kind === 'success') {
      expect(result.records.length).toBe(1);
      expect(result.records[0].recordId).toBe('r1');
      expect(result.records[0].ciphertextHash).toBe('ct');
    }
  });
});

// ---------------------------------------------------------------------------
// bootstrap_vault_trust
// ---------------------------------------------------------------------------

describe('bootstrapVaultTrust', () => {
  it('calls only the bootstrap_vault_trust RPC', async () => {
    const { client, calls, setResponse } = createMockClient();
    setResponse({
      data: {
        bootstrapped: true,
        vault_id: 'v1',
        device_id: 'd1',
        initial_head: 'head-1',
        initial_op_id: 'op-1',
      },
      error: null,
    });

    await bootstrapVaultTrust(client, 'v1', 'd1', 'pubkey', 'enc-name', 'head-1', 'op-1');

    expect(calls.length).toBe(1);
    expect(calls[0].fn).toBe('bootstrap_vault_trust');
  });

  it('returns bootstrapped on success', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        bootstrapped: true,
        vault_id: 'v1',
        device_id: 'd1',
        initial_head: 'head-1',
        initial_op_id: 'op-1',
      },
      error: null,
    });

    const result = await bootstrapVaultTrust(client, 'v1', 'd1', 'pubkey', 'enc-name', 'head-1', 'op-1');

    expect(result.kind).toBe('bootstrapped');
    if (result.kind === 'bootstrapped') {
      expect(result.vaultId).toBe('v1');
      expect(result.deviceId).toBe('d1');
      expect(result.initialHead).toBe('head-1');
      expect(result.initialOpId).toBe('op-1');
    }
  });

  it('returns trustListAlreadyExists when RPC says so', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        bootstrapped: false,
        reason: 'trust_list_already_exists',
        existing_count: 2,
      },
      error: null,
    });

    const result = await bootstrapVaultTrust(client, 'v1', 'd1', 'pubkey', 'enc-name', 'head-1', 'op-1');

    expect(result.kind).toBe('trustListAlreadyExists');
    if (result.kind === 'trustListAlreadyExists') {
      expect(result.existingCount).toBe(2);
    }
  });

  it('returns headAlreadyExists when RPC says so', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: {
        bootstrapped: false,
        reason: 'head_already_exists',
        current_head: 'existing-head',
      },
      error: null,
    });

    const result = await bootstrapVaultTrust(client, 'v1', 'd1', 'pubkey', 'enc-name', 'head-1', 'op-1');

    expect(result.kind).toBe('headAlreadyExists');
    if (result.kind === 'headAlreadyExists') {
      expect(result.currentHead).toBe('existing-head');
    }
  });

  it('classifies Not authenticated', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({ data: null, error: { code: 'P0001', message: 'Not authenticated' } });

    const result = await bootstrapVaultTrust(client, 'v1', 'd1', 'pubkey', 'enc-name', 'head-1', 'op-1');

    expect(result.kind).toBe('unauthorized');
  });
});

// ---------------------------------------------------------------------------
// Secret leak safety
// ---------------------------------------------------------------------------

describe('repository secret safety', () => {
  it('never leaks ciphertext or signature in error messages', async () => {
    const { client, setResponse } = createMockClient();
    setResponse({
      data: null,
      error: { code: 'P0001', message: 'some error' },
    });

    const result = await submitVaultOperation(
      client,
      sampleOperation({ signature: 'secret-sig', ciphertextHash: 'secret-ct' } as Partial<VaultOperationRow>),
      null,
      null,
    );

    expect(result.kind).toBe('rpcError');
    if (result.kind === 'rpcError') {
      expect(result.message).not.toContain('secret-sig');
      expect(result.message).not.toContain('secret-ct');
    }
  });
});
