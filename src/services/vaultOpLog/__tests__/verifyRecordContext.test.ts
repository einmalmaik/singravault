// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for `verifyRecordContext` — Phase 5 record context gate.
 *
 * Invariants under test:
 * - Valid record + valid operation → validContext, mayDecrypt true.
 * - AAD hash mismatch → aadMismatch, mayDecrypt false.
 * - Ciphertext hash mismatch → ciphertextHashMismatch, mayDecrypt false.
 * - lastOpId / lastOpHash mismatch → lastOpIdMismatch, mayDecrypt false.
 * - Payload hash mismatch (operation vs record) → payloadHashMismatch, mayDecrypt false.
 * - Tombstone flag inconsistent with operation type → invalidSchema.
 */

import { describe, expect, it } from 'vitest';
import { buildRecordAad } from '../recordAad';
import { computeAadHash, computeCiphertextHash } from '../recordHashes';
import { verifyRecordContext } from '../verifyRecordContext';
import type { VaultOperationRow, VaultRecordRow } from '../vaultOpLogRpcTypes';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const VAULT_ID = 'vault-1';
const RECORD_ID = 'record-1';
const OP_ID = 'op-1';
const OP_HASH = 'op-hash-1';

async function makeMinimalRecord(overrides: Partial<VaultRecordRow> = {}): Promise<VaultRecordRow> {
  const recordVersion = overrides.recordVersion ?? 1;
  const keyVersion = overrides.keyVersion ?? 1;
  const recordType = overrides.recordType ?? 'item';

  const aad = buildRecordAad({
    vaultId: VAULT_ID,
    recordId: RECORD_ID,
    recordType: recordType as 'item' | 'category' | 'attachment_metadata' | 'attachment_chunk' | 'manifest' | 'tombstone',
    recordVersion,
    keyVersion,
  });

  const aadHash = await computeAadHash(aad);
  const nonce = 'nonce-test-b64url';
  const ciphertext = 'ciphertext-test-b64url';

  const ciphertextHash = await computeCiphertextHash({
    aadHash,
    nonceB64Url: nonce,
    ciphertextB64Url: ciphertext,
    vaultId: VAULT_ID,
    recordId: RECORD_ID,
    recordType,
    recordVersion,
    keyVersion,
  });

  return {
    vaultId: VAULT_ID,
    recordId: RECORD_ID,
    recordType: recordType as 'item' | 'category' | 'attachment_metadata' | 'attachment_chunk' | 'manifest' | 'tombstone',
    recordVersion,
    keyVersion,
    aadHash,
    ciphertextHash,
    nonce,
    ciphertext,
    lastOpId: OP_ID,
    lastOpHash: OP_HASH,
    isTombstone: false,
    createdAt: '2026-05-01T00:00:00.000Z',
    updatedAt: '2026-05-01T00:00:00.000Z',
    ...overrides,
  };
}

function makeMinimalOperation(overrides: Partial<VaultOperationRow> = {}): VaultOperationRow {
  return {
    opId: OP_ID,
    opHash: OP_HASH,
    vaultId: VAULT_ID,
    authorDeviceId: 'device-1',
    opType: 'create',
    recordId: RECORD_ID,
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'new-hash',
    baseVaultHead: null,
    resultingVaultHead: 'result-hash',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'ct-hash',
    payloadAadHash: 'aad-hash',
    signedBody: {},
    signature: 'sig-test',
    signatureSchema: 'device-signature-v1',
    trustEpoch: 0,
    createdAtClient: '2026-05-01T00:00:00.000Z',
    receivedAtServer: '',
    sequenceNumber: 0,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

describe('verifyRecordContext — positive path', () => {
  it('returns validContext when record metadata, hashes and operation linkage match', async () => {
    const record = await makeMinimalRecord();
    const operation = makeMinimalOperation({
      payloadCiphertextHash: record.ciphertextHash,
      payloadAadHash: record.aadHash,
    });
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('validContext');
    expect(result.mayDecrypt).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Negative paths — no decrypt
// ---------------------------------------------------------------------------

describe('verifyRecordContext — hash and linkage failures', () => {
  it('returns aadMismatch when the stored aadHash does not match recomputed hash', async () => {
    const record = await makeMinimalRecord({ aadHash: 'tampered-aad-hash' });
    const operation = makeMinimalOperation();
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('aadMismatch');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns ciphertextHashMismatch when the stored ciphertextHash does not match', async () => {
    const record = await makeMinimalRecord({ ciphertextHash: 'tampered-ct-hash' });
    const operation = makeMinimalOperation();
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('ciphertextHashMismatch');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns lastOpIdMismatch when lastOpId does not match the operation opId', async () => {
    const record = await makeMinimalRecord({ lastOpId: 'different-op-id' });
    const operation = makeMinimalOperation();
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('lastOpIdMismatch');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns lastOpIdMismatch when lastOpHash does not match the operation opHash', async () => {
    const record = await makeMinimalRecord({ lastOpHash: 'different-op-hash' });
    const operation = makeMinimalOperation();
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('lastOpIdMismatch');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns payloadHashMismatch when payloadCiphertextHash does not match record', async () => {
    const record = await makeMinimalRecord();
    const operation = makeMinimalOperation({
      payloadCiphertextHash: 'different-ct-hash',
      payloadAadHash: record.aadHash,
    });
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('payloadHashMismatch');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns payloadHashMismatch when payloadAadHash does not match record', async () => {
    const record = await makeMinimalRecord();
    const operation = makeMinimalOperation({
      payloadCiphertextHash: record.ciphertextHash,
      payloadAadHash: 'different-aad-hash',
    });
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('payloadHashMismatch');
    expect(result.mayDecrypt).toBe(false);
  });
});

describe('verifyRecordContext — tombstone consistency', () => {
  it('returns invalidSchema when a delete operation points to a non-tombstone record', async () => {
    const record = await makeMinimalRecord({ isTombstone: false });
    const operation = makeMinimalOperation({
      opType: 'delete',
      payloadCiphertextHash: record.ciphertextHash,
      payloadAadHash: record.aadHash,
    });
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('invalidSchema');
    expect(result.mayDecrypt).toBe(false);
  });

  it('returns invalidSchema when a non-delete operation points to a tombstone record', async () => {
    const record = await makeMinimalRecord({ isTombstone: true });
    const operation = makeMinimalOperation({
      opType: 'update',
      payloadCiphertextHash: record.ciphertextHash,
      payloadAadHash: record.aadHash,
    });
    const result = await verifyRecordContext({ record, operation });
    expect(result.kind).toBe('invalidSchema');
    expect(result.mayDecrypt).toBe(false);
  });
});
