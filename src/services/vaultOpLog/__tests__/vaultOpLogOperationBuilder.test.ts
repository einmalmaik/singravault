// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the vault operation builder (Phase 4).
 *
 * Coverage:
 * - Create / Update / Delete produce complete signed bodies.
 * - intent_id, op_id, base_vault_head, previous_ciphertext_hash are
 *   set correctly per operation type.
 * - op_hash is stable for identical inputs and unique for differing
 *   inputs (sensitivity).
 * - Signature verifies against the generated public key.
 * - resultingVaultHead is non-empty and changes with inputs.
 * - toVaultOperationRow / toVaultRecordRow produce valid domain rows.
 * - No plaintext leaks in the built output.
 * - Restore is rejected in Phase 4.
 */

import { describe, expect, it } from 'vitest';
import {
  buildCreateRecordOperation,
  buildUpdateRecordOperation,
  buildDeleteRecordOperation,
  buildRestoreRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
  VaultOperationBuilderError,
} from '../vaultOpLogOperationBuilder';
import {
  generateDeviceSigningKeyPair,
  verifyOperationSignature,
} from '../operationSigningService';
import { computeOpHash } from '../recordHashes';
import { deriveRecordKey, sealRecord } from '../cryptoRecordService';
import { DEVICE_SIGNATURE_SCHEMA_V1, isRecordType } from '../types';

async function signingFixture() {
  const pair = await generateDeviceSigningKeyPair();
  return pair;
}

function vaultKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

const VAULT_ID = 'vault-1';
const RECORD_ID = 'rec-1';
const DEVICE_ID = 'dev-1';

// ---------------------------------------------------------------------------
// create
// ---------------------------------------------------------------------------

describe('buildCreateRecordOperation', () => {
  it('produces a signed operation with correct fields for create', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();
    const plaintext = new TextEncoder().encode('secret payload');

    const built = await buildCreateRecordOperation({
      opId: 'op-create-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-0',
      vaultEncryptionKey: vaultEncKey,
      plaintext,
      keyVersion: 1,
    });

    const body = built.signedOperation.body;
    expect(body.opType).toBe('create');
    expect(body.opId).toBe('op-create-1');
    expect(body.intentId).toBe('intent-1');
    expect(body.rebasedFromOpId).toBeNull();
    expect(body.vaultId).toBe(VAULT_ID);
    expect(body.recordId).toBe(RECORD_ID);
    expect(body.baseRecordVersion).toBeNull();
    expect(body.previousCiphertextHash).toBeNull();
    expect(body.newRecordHash).toBe(built.sealedRecord.ciphertextHash);
    expect(body.baseVaultHead).toBe('head-0');
    expect(body.signatureSchema).toBe(DEVICE_SIGNATURE_SCHEMA_V1);
    expect(built.signedOperation.signature.length).toBeGreaterThan(0);
    expect(built.resultingVaultHead.length).toBeGreaterThan(0);
  });

  it('has a verifiable signature', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const vaultEncKey = vaultKey();
    const built = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('x'),
      keyVersion: 1,
    });

    const verified = await verifyOperationSignature(built.signedOperation, publicKey);
    expect(verified).toBe(true);
  });

  it('produces a deterministic op_hash from the same signed body', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-0',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('same'),
      keyVersion: 1,
      createdAtClient: '2026-05-01T00:00:00.000Z',
    });

    // Recompute opHash from the same body to prove determinism.
    const recomputed = await computeOpHash(built.signedOperation.body);
    expect(built.signedOperation.opHash).toBe(recomputed);
  });

  it('produces a different op_hash when intent_id differs', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();
    const plaintext = new TextEncoder().encode('same');

    const a = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-a',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-0',
      vaultEncryptionKey: vaultEncKey,
      plaintext,
      keyVersion: 1,
      createdAtClient: '2026-05-01T00:00:00.000Z',
    });

    const b = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-b',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-0',
      vaultEncryptionKey: vaultEncKey,
      plaintext,
      keyVersion: 1,
      createdAtClient: '2026-05-01T00:00:00.000Z',
    });

    expect(a.signedOperation.opHash).not.toBe(b.signedOperation.opHash);
  });

  it('resultingVaultHead changes when baseVaultHead changes', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const a = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-a',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('x'),
      keyVersion: 1,
    });

    const b = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-b',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('x'),
      keyVersion: 1,
    });

    expect(a.resultingVaultHead).not.toBe(b.resultingVaultHead);
  });
});

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------

describe('buildUpdateRecordOperation', () => {
  it('sets baseRecordVersion and previousCiphertextHash for update', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildUpdateRecordOperation({
      opId: 'op-up-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-1',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('updated'),
      keyVersion: 1,
      baseRecordVersion: 2,
      previousCiphertextHash: 'prev-hash',
    });

    const body = built.signedOperation.body;
    expect(body.opType).toBe('update');
    expect(body.baseRecordVersion).toBe(2);
    expect(body.previousCiphertextHash).toBe('prev-hash');
    expect(built.sealedRecord.aad.recordVersion).toBe(3); // base + 1
  });
});

// ---------------------------------------------------------------------------
// delete
// ---------------------------------------------------------------------------

describe('buildDeleteRecordOperation', () => {
  it('produces a tombstone record and marks opType delete', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildDeleteRecordOperation({
      opId: 'op-del-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-1',
      vaultEncryptionKey: vaultEncKey,
      keyVersion: 1,
      baseRecordVersion: 2,
      previousCiphertextHash: 'prev-hash',
    });

    const body = built.signedOperation.body;
    expect(body.opType).toBe('delete');
    expect(body.baseRecordVersion).toBe(2);
    expect(body.previousCiphertextHash).toBe('prev-hash');
    expect(built.sealedRecord.aad.recordType).toBe('tombstone');
    expect(built.sealedRecord.aad.recordVersion).toBe(3);
  });

  it('has a verifiable signature', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildDeleteRecordOperation({
      opId: 'op-del-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-1',
      vaultEncryptionKey: vaultEncKey,
      keyVersion: 1,
      baseRecordVersion: 2,
      previousCiphertextHash: 'prev-hash',
    });

    const verified = await verifyOperationSignature(built.signedOperation, publicKey);
    expect(verified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// restore — not implemented in Phase 4
// ---------------------------------------------------------------------------

describe('buildRestoreRecordOperation', () => {
  it('produces a signed restore operation in Phase 6', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const result = await buildRestoreRecordOperation({
      opId: 'op-res-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-1',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('restored'),
      keyVersion: 1,
      baseRecordVersion: 2,
      previousCiphertextHash: 'prev-hash',
    });

    expect(result.signedOperation.body.opType).toBe('restore');
    expect(result.signedOperation.body.recordId).toBe(RECORD_ID);
    expect(result.sealedRecord.aad.recordVersion).toBe(3);
    expect(result.signedOperation.signature).not.toBe('');
  });
});

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

describe('toVaultOperationRow', () => {
  it('maps a built create operation to a domain row', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: 'head-0',
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('x'),
      keyVersion: 1,
    });

    const row = toVaultOperationRow(built);
    expect(row.opId).toBe('op-1');
    expect(row.opHash).toBe(built.signedOperation.opHash);
    expect(row.resultingVaultHead).toBe(built.resultingVaultHead);
    expect(row.signature).toBe(built.signedOperation.signature);
    expect(row.receivedAtServer).toBe('');
    expect(row.sequenceNumber).toBe(0);
  });
});

describe('toVaultRecordRow', () => {
  it('maps a sealed record to a domain row', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();

    const built = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      vaultEncryptionKey: vaultEncKey,
      plaintext: new TextEncoder().encode('x'),
      keyVersion: 1,
    });

    const opRow = toVaultOperationRow(built);
    const recRow = toVaultRecordRow(built.sealedRecord, opRow, false);

    expect(recRow.recordId).toBe(RECORD_ID);
    expect(recRow.recordType).toBe('item');
    expect(recRow.vaultId).toBe(VAULT_ID);
    expect(recRow.lastOpId).toBe('op-1');
    expect(recRow.lastOpHash).toBe(built.signedOperation.opHash);
    expect(recRow.isTombstone).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Secret / plaintext leak check
// ---------------------------------------------------------------------------

describe('builder secret safety', () => {
  it('does not include plaintext in the operation body or record row', async () => {
    const { privateKey } = await signingFixture();
    const vaultEncKey = vaultKey();
    const plaintext = new TextEncoder().encode('my-secret-password');

    const built = await buildCreateRecordOperation({
      opId: 'op-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      recordId: RECORD_ID,
      recordType: 'item',
      deviceId: DEVICE_ID,
      deviceSigningKey: privateKey,
      trustEpoch: 0,
      baseVaultHead: null,
      vaultEncryptionKey: vaultEncKey,
      plaintext,
      keyVersion: 1,
    });

    const bodyJson = JSON.stringify(built.signedOperation.body);
    expect(bodyJson).not.toContain('my-secret-password');

    const opRow = toVaultOperationRow(built);
    const rowJson = JSON.stringify(opRow);
    expect(rowJson).not.toContain('my-secret-password');
  });
});
