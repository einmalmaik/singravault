// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for `verifyOperation` — Phase 5 operation verification gate.
 *
 * Invariants under test:
 * - Valid signed operation from a trusted device → validTrustedOperation.
 * - Unknown author → quarantinedUnknownAuthor, no decrypt implied.
 * - Revoked author → revokedAuthor.
 * - Invalid signature → quarantinedTampered.
 * - Op hash mismatch → quarantinedTampered.
 * - Unsupported operation type → quarantinedTampered.
 * - Causal gap / conflict candidate detected when local state diverges.
 */

import { describe, expect, it } from 'vitest';
import {
  buildOperationSignedBody,
  generateDeviceSigningKeyPair,
  signOperation,
} from '../operationSigningService';
import { verifyOperation } from '../verifyOperation';
import type { SignedVaultOperationV1, TrustedDeviceRecordV1 } from '../types';
import type { VaultOperationRow } from '../vaultOpLogRpcTypes';
import type { TrustListInput } from '../deviceTrustService';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function buildTrustedDevice(overrides: Partial<TrustedDeviceRecordV1> = {}): TrustedDeviceRecordV1 {
  return {
    vaultId: 'vault-1',
    deviceId: 'device-1',
    publicSigningKey: 'pub-key-b64url',
    deviceNameEncrypted: 'enc:name',
    addedByDeviceId: null,
    addedAt: '2026-01-01T00:00:00.000Z',
    trustEpoch: 0,
    status: 'trusted',
    revokedAt: null,
    revokedByDeviceId: null,
    ...overrides,
  };
}

function baseBodyInput(overrides: Partial<Parameters<typeof buildOperationSignedBody>[0]> = {}) {
  return {
    opId: 'op-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId: 'vault-1',
    authorDeviceId: 'device-1',
    opType: 'create' as const,
    recordId: 'record-1',
    recordType: 'item' as const,
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'new-hash',
    baseVaultHead: null,
    payloadCiphertextHash: 'ct-hash',
    payloadAadHash: 'aad-hash',
    createdAtClient: '2026-05-02T10:00:00.000Z',
    trustEpoch: 0,
    ...overrides,
  };
}

async function buildSignedOperation(
  overrides: Partial<Parameters<typeof buildOperationSignedBody>[0]> = {},
) {
  const keyPair = await generateDeviceSigningKeyPair();
  const body = buildOperationSignedBody(baseBodyInput(overrides));
  const signed = await signOperation(body, keyPair.privateKey);
  return { signed, publicKey: keyPair.publicKey };
}

function toVaultOperationRow(signed: SignedVaultOperationV1): VaultOperationRow {
  return {
    opId: signed.body.opId,
    opHash: signed.opHash,
    vaultId: signed.body.vaultId,
    authorDeviceId: signed.body.authorDeviceId,
    opType: signed.body.opType,
    recordId: signed.body.recordId,
    recordType: signed.body.recordType,
    baseRecordVersion: signed.body.baseRecordVersion,
    previousCiphertextHash: signed.body.previousCiphertextHash,
    newRecordHash: signed.body.newRecordHash,
    baseVaultHead: signed.body.baseVaultHead,
    resultingVaultHead: 'resulting-head-placeholder',
    intentId: signed.body.intentId,
    rebasedFromOpId: signed.body.rebasedFromOpId,
    payloadCiphertextHash: signed.body.payloadCiphertextHash,
    payloadAadHash: signed.body.payloadAadHash,
    signedBody: signed.body,
    signature: signed.signature,
    signatureSchema: signed.body.signatureSchema,
    trustEpoch: signed.body.trustEpoch,
    createdAtClient: signed.body.createdAtClient,
    receivedAtServer: '',
    sequenceNumber: 0,
  };
}

function buildTrust(deviceId: string, overrides: Partial<TrustedDeviceRecordV1> = {}): TrustListInput {
  return {
    vaultId: 'vault-1',
    trustedDevicesById: new Map([[deviceId, buildTrustedDevice({ deviceId, ...overrides })]]),
  };
}

// ---------------------------------------------------------------------------
// Positive path
// ---------------------------------------------------------------------------

describe('verifyOperation — positive path', () => {
  it('returns validTrustedOperation for a correctly signed create from a trusted device', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('validTrustedOperation');
    if (result.kind === 'validTrustedOperation') {
      expect(result.signedOperation.body.opId).toBe('op-1');
    }
  });
});

// ---------------------------------------------------------------------------
// Negative paths — no decrypt implied (verifyOperation never decrypts)
// ---------------------------------------------------------------------------

describe('verifyOperation — unknown / revoked author', () => {
  it('returns unknownAuthor when the device is not in the trust list', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: { vaultId: 'vault-1', trustedDevicesById: new Map() },
      publicKey,
    });
    expect(result.kind).toBe('unknownAuthor');
  });

  it('returns revokedAuthor when the device is revoked', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1', { status: 'revoked', revokedAt: '2026-05-01T00:00:00.000Z' }),
      publicKey,
    });
    expect(result.kind).toBe('revokedAuthor');
  });
});

describe('verifyOperation — signature and hash integrity', () => {
  it('returns invalidSignature when the signature is tampered', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    // Tamper the signature (flip a character)
    const tamperedRow: VaultOperationRow = {
      ...row,
      signature: row.signature.slice(0, -1) + (row.signature.slice(-1) === 'A' ? 'B' : 'A'),
    };
    const result = await verifyOperation({
      operation: tamperedRow,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('invalidSignature');
  });

  it('returns opHashMismatch when the opHash does not match the canonical body', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const tamperedRow: VaultOperationRow = {
      ...row,
      opHash: 'tampered-op-hash',
    };
    const result = await verifyOperation({
      operation: tamperedRow,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('opHashMismatch');
  });
});

describe('verifyOperation — operation type and payload constraints', () => {
  it('returns unsupportedOperationType for a create carrying base fields', async () => {
    const { signed, publicKey } = await buildSignedOperation({
      opType: 'create',
      baseRecordVersion: 1,
      previousCiphertextHash: 'prev-hash',
    });
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('unsupportedOperationType');
  });

  it('returns payloadHashMismatch for an update missing newRecordHash', async () => {
    const { signed, publicKey } = await buildSignedOperation({
      opType: 'update',
      baseRecordVersion: 1,
      previousCiphertextHash: 'prev-hash',
      newRecordHash: null,
      payloadCiphertextHash: null,
      payloadAadHash: null,
    });
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('payloadHashMismatch');
  });
});

describe('verifyOperation — causal consistency with local state', () => {
  it('returns conflictCandidate when a verified record already exists and a create arrives', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
      localRecordState: { recordVersion: 1, ciphertextHash: 'local-hash' },
    });
    expect(result.kind).toBe('conflictCandidate');
  });

  it('returns causalGap when an update targets a missing local record', async () => {
    const { signed, publicKey } = await buildSignedOperation({
      opType: 'update',
      baseRecordVersion: 1,
      previousCiphertextHash: 'prev-hash',
    });
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
      localRecordState: null,
    });
    expect(result.kind).toBe('causalGap');
  });

  it('returns rollbackSuspected when previousCiphertextHash differs from local', async () => {
    const { signed, publicKey } = await buildSignedOperation({
      opType: 'update',
      baseRecordVersion: 1,
      previousCiphertextHash: 'prev-hash-remote',
    });
    const row = toVaultOperationRow(signed);
    const result = await verifyOperation({
      operation: row,
      trust: buildTrust('device-1'),
      publicKey,
      localRecordState: { recordVersion: 1, ciphertextHash: 'prev-hash-local' },
    });
    expect(result.kind).toBe('rollbackSuspected');
  });
});

describe('verifyOperation — signed body structural validation', () => {
  it('returns requiresLockedCritical when signedBody is not an object', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const malformed: VaultOperationRow = { ...row, signedBody: 'not-an-object' };
    const result = await verifyOperation({
      operation: malformed,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('requiresLockedCritical');
  });

  it('returns requiresLockedCritical when signedBody misses required fields', async () => {
    const { signed, publicKey } = await buildSignedOperation();
    const row = toVaultOperationRow(signed);
    const malformed: VaultOperationRow = { ...row, signedBody: { opId: 'op-1' } };
    const result = await verifyOperation({
      operation: malformed,
      trust: buildTrust('device-1'),
      publicKey,
    });
    expect(result.kind).toBe('requiresLockedCritical');
  });
});
