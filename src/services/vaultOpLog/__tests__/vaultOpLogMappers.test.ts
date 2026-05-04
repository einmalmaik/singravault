// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for vault operation log DB -> domain mappers.
 *
 * Coverage:
 * - All security-relevant fields are preserved during mapping.
 * - Missing mandatory fields cause VaultOpLogMapperError.
 * - Unknown non-security fields do not break parsing.
 * - signed_body survives a JSONB-like roundtrip and re-canonicalisation.
 * - op_hash remains stable after JSONB roundtrip.
 */

import { describe, expect, it } from 'vitest';
import { canonicalizeVaultStructure, canonicalizeVaultStructureAsString } from '../canonicalJson';
import { computeOpHash } from '../recordHashes';
import {
  mapDbHeadRowToDomain,
  mapDbOperationRowToDomain,
  mapDbRecordRowToDomain,
  VaultOpLogMapperError,
  buildSubmitVaultOperationRequest,
  buildGetVaultHeadRequest,
  buildGetVaultChangesSinceRequest,
  buildGetVaultRecordsByIdsRequest,
  buildBootstrapVaultTrustRequest,
} from '../vaultOpLogMappers';
import { isVaultOpLogRepositoryEnabled } from '../vaultOpLogFeatureFlags';
import type { VaultOperationRow, VaultRecordRow, VaultHeadRow } from '../vaultOpLogRpcTypes';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';

// ---------------------------------------------------------------------------
// Fixtures (no real secrets — all values are deterministic test tokens)
// ---------------------------------------------------------------------------

function makeMinimalDbOperation(extra?: Record<string, unknown>) {
  return {
    op_id: '550e8400-e29b-41d4-a716-446655440000',
    op_hash: 'op-hash-test',
    vault_id: '550e8400-e29b-41d4-a716-446655440001',
    author_device_id: '550e8400-e29b-41d4-a716-446655440002',
    op_type: 'create',
    record_id: '550e8400-e29b-41d4-a716-446655440003',
    record_type: 'item',
    base_record_version: null,
    previous_ciphertext_hash: null,
    new_record_hash: 'new-hash',
    base_vault_head: null,
    resulting_vault_head: 'result-hash',
    intent_id: '550e8400-e29b-41d4-a716-446655440004',
    rebased_from_op_id: null,
    payload_ciphertext_hash: 'ct-hash',
    payload_aad_hash: 'aad-hash',
    signed_body: {
      signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
      opId: '550e8400-e29b-41d4-a716-446655440000',
      intentId: '550e8400-e29b-41d4-a716-446655440004',
      rebasedFromOpId: null,
      vaultId: '550e8400-e29b-41d4-a716-446655440001',
      authorDeviceId: '550e8400-e29b-41d4-a716-446655440002',
      opType: 'create',
      recordId: '550e8400-e29b-41d4-a716-446655440003',
      recordType: 'item',
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: 'new-hash',
      baseVaultHead: null,
      payloadCiphertextHash: 'ct-hash',
      payloadAadHash: 'aad-hash',
      createdAtClient: '2026-05-01T00:00:00.000Z',
      trustEpoch: 0,
    },
    signature: 'sig-test',
    signature_schema: DEVICE_SIGNATURE_SCHEMA_V1,
    trust_epoch: 0,
    created_at_client: '2026-05-01T00:00:00.000Z',
    received_at_server: '2026-05-01T00:00:01.000Z',
    sequence_number: 1,
    ...extra,
  };
}

function makeMinimalDbRecord(extra?: Record<string, unknown>) {
  return {
    vault_id: '550e8400-e29b-41d4-a716-446655440001',
    record_id: '550e8400-e29b-41d4-a716-446655440003',
    record_type: 'item',
    record_version: 1,
    key_version: 1,
    aad_hash: 'aad-hash',
    ciphertext_hash: 'ct-hash',
    nonce: 'nonce-test',
    ciphertext: 'cipher-test',
    last_op_id: '550e8400-e29b-41d4-a716-446655440000',
    last_op_hash: 'op-hash-test',
    is_tombstone: false,
    created_at: '2026-05-01T00:00:00.000Z',
    updated_at: '2026-05-01T00:00:01.000Z',
    ...extra,
  };
}

function makeMinimalDbHead(extra?: Record<string, unknown>) {
  return {
    vault_id: '550e8400-e29b-41d4-a716-446655440001',
    current_head: 'head-hash',
    current_op_id: '550e8400-e29b-41d4-a716-446655440000',
    current_sequence_number: 1,
    updated_at: '2026-05-01T00:00:01.000Z',
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// DB -> Domain mapping — field completeness
// ---------------------------------------------------------------------------

describe('mapDbOperationRowToDomain', () => {
  it('preserves all security-relevant fields', () => {
    const db = makeMinimalDbOperation();
    const mapped = mapDbOperationRowToDomain(db);

    expect(mapped.opId).toBe(db.op_id);
    expect(mapped.opHash).toBe(db.op_hash);
    expect(mapped.vaultId).toBe(db.vault_id);
    expect(mapped.authorDeviceId).toBe(db.author_device_id);
    expect(mapped.opType).toBe(db.op_type);
    expect(mapped.recordId).toBe(db.record_id);
    expect(mapped.recordType).toBe(db.record_type);
    expect(mapped.baseRecordVersion).toBe(db.base_record_version);
    expect(mapped.previousCiphertextHash).toBe(db.previous_ciphertext_hash);
    expect(mapped.newRecordHash).toBe(db.new_record_hash);
    expect(mapped.baseVaultHead).toBe(db.base_vault_head);
    expect(mapped.resultingVaultHead).toBe(db.resulting_vault_head);
    expect(mapped.intentId).toBe(db.intent_id);
    expect(mapped.rebasedFromOpId).toBe(db.rebased_from_op_id);
    expect(mapped.payloadCiphertextHash).toBe(db.payload_ciphertext_hash);
    expect(mapped.payloadAadHash).toBe(db.payload_aad_hash);
    expect(mapped.signedBody).toEqual(db.signed_body);
    expect(mapped.signature).toBe(db.signature);
    expect(mapped.signatureSchema).toBe(db.signature_schema);
    expect(mapped.trustEpoch).toBe(db.trust_epoch);
    expect(mapped.createdAtClient).toBe(db.created_at_client);
    expect(mapped.receivedAtServer).toBe(db.received_at_server);
    expect(mapped.sequenceNumber).toBe(db.sequence_number);
  });

  it('throws on missing op_id', () => {
    const db = makeMinimalDbOperation();
    delete (db as Record<string, unknown>).op_id;
    expect(() => mapDbOperationRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });

  it('throws on missing op_hash', () => {
    const db = makeMinimalDbOperation();
    delete (db as Record<string, unknown>).op_hash;
    expect(() => mapDbOperationRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });

  it('throws on missing signed_body', () => {
    const db = makeMinimalDbOperation();
    delete (db as Record<string, unknown>).signed_body;
    expect(() => mapDbOperationRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });

  it('throws on invalid op_type', () => {
    const db = makeMinimalDbOperation({ op_type: 'invalid_op' });
    expect(() => mapDbOperationRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });

  it('throws on invalid record_type', () => {
    const db = makeMinimalDbOperation({ record_type: 'invalid_type' });
    expect(() => mapDbOperationRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });

  it('does not break on harmless extra fields', () => {
    const db = makeMinimalDbOperation({ extra_field: 'harmless' });
    const mapped = mapDbOperationRowToDomain(db);
    expect(mapped.opId).toBe(db.op_id);
  });

  it('maps null base_record_version to null', () => {
    const db = makeMinimalDbOperation({ base_record_version: null });
    const mapped = mapDbOperationRowToDomain(db);
    expect(mapped.baseRecordVersion).toBeNull();
  });

  it('maps numeric base_record_version', () => {
    const db = makeMinimalDbOperation({ op_type: 'update', base_record_version: 3 });
    const mapped = mapDbOperationRowToDomain(db);
    expect(mapped.baseRecordVersion).toBe(3);
  });
});

describe('mapDbRecordRowToDomain', () => {
  it('preserves all security-relevant fields', () => {
    const db = makeMinimalDbRecord();
    const mapped = mapDbRecordRowToDomain(db);

    expect(mapped.vaultId).toBe(db.vault_id);
    expect(mapped.recordId).toBe(db.record_id);
    expect(mapped.recordType).toBe(db.record_type);
    expect(mapped.recordVersion).toBe(db.record_version);
    expect(mapped.keyVersion).toBe(db.key_version);
    expect(mapped.aadHash).toBe(db.aad_hash);
    expect(mapped.ciphertextHash).toBe(db.ciphertext_hash);
    expect(mapped.nonce).toBe(db.nonce);
    expect(mapped.ciphertext).toBe(db.ciphertext);
    expect(mapped.lastOpId).toBe(db.last_op_id);
    expect(mapped.lastOpHash).toBe(db.last_op_hash);
    expect(mapped.isTombstone).toBe(db.is_tombstone);
    expect(mapped.createdAt).toBe(db.created_at);
    expect(mapped.updatedAt).toBe(db.updated_at);
  });

  it('throws on missing ciphertext_hash', () => {
    const db = makeMinimalDbRecord();
    delete (db as Record<string, unknown>).ciphertext_hash;
    expect(() => mapDbRecordRowToDomain(db)).toThrow(VaultOpLogMapperError);
  });
});

describe('mapDbHeadRowToDomain', () => {
  it('preserves all fields', () => {
    const db = makeMinimalDbHead();
    const mapped = mapDbHeadRowToDomain(db);

    expect(mapped.vaultId).toBe(db.vault_id);
    expect(mapped.currentHead).toBe(db.current_head);
    expect(mapped.currentOpId).toBe(db.current_op_id);
    expect(mapped.currentSequenceNumber).toBe(db.current_sequence_number);
    expect(mapped.updatedAt).toBe(db.updated_at);
  });

  it('maps null current_op_id', () => {
    const db = makeMinimalDbHead({ current_op_id: null });
    const mapped = mapDbHeadRowToDomain(db);
    expect(mapped.currentOpId).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Domain -> RPC request builders
// ---------------------------------------------------------------------------

describe('buildSubmitVaultOperationRequest', () => {
  it('produces snake_case keys for the RPC', () => {
    const op = mapDbOperationRowToDomain(makeMinimalDbOperation());
    const req = buildSubmitVaultOperationRequest(op, null, null);

    expect(req.p_op.op_id).toBe(op.opId);
    expect(req.p_op.op_hash).toBe(op.opHash);
    expect(req.p_op.vault_id).toBe(op.vaultId);
    expect(req.p_op.author_device_id).toBe(op.authorDeviceId);
    expect(req.p_op.op_type).toBe(op.opType);
    expect(req.p_op.record_id).toBe(op.recordId);
    expect(req.p_op.record_type).toBe(op.recordType);
    expect(req.p_op.base_record_version).toBe(op.baseRecordVersion);
    expect(req.p_op.previous_ciphertext_hash).toBe(op.previousCiphertextHash);
    expect(req.p_op.new_record_hash).toBe(op.newRecordHash);
    expect(req.p_op.base_vault_head).toBe(op.baseVaultHead);
    expect(req.p_op.resulting_vault_head).toBe(op.resultingVaultHead);
    expect(req.p_op.intent_id).toBe(op.intentId);
    expect(req.p_op.rebased_from_op_id).toBe(op.rebasedFromOpId);
    expect(req.p_op.payload_ciphertext_hash).toBe(op.payloadCiphertextHash);
    expect(req.p_op.payload_aad_hash).toBe(op.payloadAadHash);
    expect(req.p_op.signed_body).toEqual(op.signedBody);
    expect(req.p_op.signature).toBe(op.signature);
    expect(req.p_op.signature_schema).toBe(op.signatureSchema);
    expect(req.p_op.trust_epoch).toBe(op.trustEpoch);
    expect(req.p_op.created_at_client).toBe(op.createdAtClient);
  });

  it('includes record_payload when provided', () => {
    const op = mapDbOperationRowToDomain(makeMinimalDbOperation());
    const payload = {
      aadHash: 'aad-2',
      ciphertextHash: 'ct-2',
      nonce: 'nonce-2',
      ciphertext: 'cipher-2',
      keyVersion: 2,
    };
    const req = buildSubmitVaultOperationRequest(op, payload, null);

    expect(req.p_record_payload).not.toBeNull();
    expect(req.p_record_payload!.aad_hash).toBe(payload.aadHash);
    expect(req.p_record_payload!.ciphertext_hash).toBe(payload.ciphertextHash);
    expect(req.p_record_payload!.nonce).toBe(payload.nonce);
    expect(req.p_record_payload!.ciphertext).toBe(payload.ciphertext);
    expect(req.p_record_payload!.key_version).toBe(payload.keyVersion);
  });

  it('sets record_payload to null when omitted', () => {
    const op = mapDbOperationRowToDomain(makeMinimalDbOperation());
    const req = buildSubmitVaultOperationRequest(op, null, null);
    expect(req.p_record_payload).toBeNull();
  });
});

describe('buildGetVaultHeadRequest', () => {
  it('wraps vault_id', () => {
    expect(buildGetVaultHeadRequest('v1')).toEqual({ p_vault_id: 'v1' });
  });
});

describe('buildGetVaultChangesSinceRequest', () => {
  it('wraps all parameters', () => {
    expect(buildGetVaultChangesSinceRequest('v1', 5, 100)).toEqual({
      p_vault_id: 'v1',
      p_since_sequence: 5,
      p_limit: 100,
    });
  });
});

describe('buildGetVaultRecordsByIdsRequest', () => {
  it('wraps vault_id and record_ids', () => {
    expect(buildGetVaultRecordsByIdsRequest('v1', ['r1', 'r2'])).toEqual({
      p_vault_id: 'v1',
      p_record_ids: ['r1', 'r2'],
    });
  });
});

describe('buildBootstrapVaultTrustRequest', () => {
  it('wraps all parameters', () => {
    expect(
      buildBootstrapVaultTrustRequest('v1', 'd1', 'pubkey', 'enc-name', 'head', 'op1'),
    ).toEqual({
      p_vault_id: 'v1',
      p_device_id: 'd1',
      p_public_signing_key: 'pubkey',
      p_device_name_encrypted: 'enc-name',
      p_initial_head: 'head',
      p_initial_op_id: 'op1',
    });
  });
});

// ---------------------------------------------------------------------------
// JSONB roundtrip and canonicalization stability
// ---------------------------------------------------------------------------

describe('signed_body JSONB roundtrip', () => {
  it('produces identical canonical bytes after JSON stringify/parse', () => {
    const signedBody = {
      signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
      opId: '550e8400-e29b-41d4-a716-446655440000',
      intentId: '550e8400-e29b-41d4-a716-446655440004',
      rebasedFromOpId: null,
      vaultId: '550e8400-e29b-41d4-a716-446655440001',
      authorDeviceId: '550e8400-e29b-41d4-a716-446655440002',
      opType: 'create',
      recordId: '550e8400-e29b-41d4-a716-446655440003',
      recordType: 'item',
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: 'new-hash',
      baseVaultHead: null,
      payloadCiphertextHash: 'ct-hash',
      payloadAadHash: 'aad-hash',
      createdAtClient: '2026-05-01T00:00:00.000Z',
      trustEpoch: 0,
    };

    const bytes1 = canonicalizeVaultStructure(signedBody);
    // Simulate JSONB roundtrip: canonical bytes -> JSON string -> parse -> re-canonicalize
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);

    expect(bytes2).toEqual(bytes1);
  });

  it('is stable when object key order is shuffled by JSONB', () => {
    // PostgreSQL JSONB reorders keys; canonicalize must sort them.
    const original = {
      zField: 1,
      aField: 2,
      mField: 3,
    };

    const bytes1 = canonicalizeVaultStructure(original);
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    // Simulate JSONB reorder: keys are alphabetically sorted by PG
    const reordered = {
      aField: parsed.aField,
      mField: parsed.mField,
      zField: parsed.zField,
    };
    const bytes2 = canonicalizeVaultStructure(reordered);

    expect(bytes2).toEqual(bytes1);
  });

  it('preserves null values through JSONB roundtrip', () => {
    const obj = { a: 1, b: null, c: 'test' };
    const bytes1 = canonicalizeVaultStructure(obj);
    const parsed = JSON.parse(new TextDecoder().decode(bytes1));
    const bytes2 = canonicalizeVaultStructure(parsed);

    expect(bytes2).toEqual(bytes1);
    expect(parsed.b).toBeNull();
  });
});

describe('op_hash stability after JSONB roundtrip', () => {
  it('produces identical op_hash before and after simulated JSONB roundtrip', async () => {
    const signedBody = {
      signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
      opId: '550e8400-e29b-41d4-a716-446655440000',
      intentId: '550e8400-e29b-41d4-a716-446655440004',
      rebasedFromOpId: null,
      vaultId: '550e8400-e29b-41d4-a716-446655440001',
      authorDeviceId: '550e8400-e29b-41d4-a716-446655440002',
      opType: 'create',
      recordId: '550e8400-e29b-41d4-a716-446655440003',
      recordType: 'item',
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: 'new-hash',
      baseVaultHead: null,
      payloadCiphertextHash: 'ct-hash',
      payloadAadHash: 'aad-hash',
      createdAtClient: '2026-05-01T00:00:00.000Z',
      trustEpoch: 0,
    };

    // Roundtrip through JSON stringify/parse to simulate JSONB storage
    const parsed = JSON.parse(JSON.stringify(signedBody));

    // op_hash is computed from the canonical signed body (without signature field)
    const hashBefore = await computeOpHash(signedBody as never);
    const hashAfter = await computeOpHash(parsed as never);

    expect(hashAfter).toBe(hashBefore);
  });
});

describe('vaultOpLogFeatureFlags', () => {
  it('defaults to false (conservative) when env variable is unset', () => {
    expect(isVaultOpLogRepositoryEnabled()).toBe(false);
  });
});
