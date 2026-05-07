// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the vault state machine — Phase 5 pipeline, state
 * classification, conflict handling, quarantine and vault security
 * mode determination.
 *
 * Security invariants under test:
 * - No record is decrypted when operation or context verification fails.
 * - Conflict between two trusted devices is conflict, not quarantine.
 * - Individual record problems do not lock the whole vault.
 * - Missing records without a valid delete are quarantinedMissingWithoutDelete.
 * - Safe mode is recommended when many records are missing or quarantined.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  buildCreateRecordOperation,
  buildDeleteRecordOperation,
  buildUpdateRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
} from '../vaultOpLogOperationBuilder';
import {
  generateDeviceSigningKeyPair,
  importDevicePublicKey,
} from '../operationSigningService';
import {
  applyRemoteOperation,
  applyTrustedDelete,
  determineVaultSecurityMode,
} from '../vaultStateMachine';
import * as cryptoRecordService from '../cryptoRecordService';
import type { LocalVaultState, LocalVerifiedRecord } from '../vaultStateMachine';
import type { TrustedDeviceRecordV1 } from '../types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVaultEncryptionKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function makePlaintext(obj: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj));
}

async function buildCreateOperationAndRecord(overrides: {
  vaultId?: string;
  recordId?: string;
  deviceId?: string;
  keyPair?: Awaited<ReturnType<typeof generateDeviceSigningKeyPair>>;
  vaultEncryptionKey?: Uint8Array;
  plaintext?: Uint8Array;
  recordType?: 'item' | 'category' | 'attachment_metadata' | 'attachment_chunk' | 'manifest';
} = {}) {
  const keyPair = overrides.keyPair ?? await generateDeviceSigningKeyPair();
  const vaultId = overrides.vaultId ?? 'vault-1';
  const recordId = overrides.recordId ?? 'record-1';
  const deviceId = overrides.deviceId ?? 'device-1';
  const vaultEncryptionKey = overrides.vaultEncryptionKey ?? makeVaultEncryptionKey();
  const plaintext = overrides.plaintext ?? makePlaintext({ name: 'Test Item' });
  const recordType = overrides.recordType ?? 'item';

  const built = await buildCreateRecordOperation({
    opId: 'op-create-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId,
    recordId,
    deviceId,
    deviceSigningKey: keyPair.privateKey,
    trustEpoch: 0,
    baseVaultHead: null,
    recordType,
    vaultEncryptionKey,
    plaintext,
    keyVersion: 1,
  });

  const opRow = toVaultOperationRow(built);
  const recRow = toVaultRecordRow(built.sealedRecord, opRow, false);

  return { built, opRow, recRow, keyPair, vaultEncryptionKey, plaintext };
}

async function buildUpdateOperationAndRecord(
  previous: Awaited<ReturnType<typeof buildCreateOperationAndRecord>>,
  overrides: {
    deviceId?: string;
    keyPair?: Awaited<ReturnType<typeof generateDeviceSigningKeyPair>>;
    plaintext?: Uint8Array;
    opId?: string;
  } = {},
) {
  const keyPair = overrides.keyPair ?? previous.keyPair;
  const deviceId = overrides.deviceId ?? previous.opRow.authorDeviceId;
  const plaintext = overrides.plaintext ?? makePlaintext({ name: 'Updated Item' });
  const opId = overrides.opId ?? 'op-update-1';

  const built = await buildUpdateRecordOperation({
    opId,
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId: previous.opRow.vaultId,
    recordId: previous.recRow.recordId,
    deviceId,
    deviceSigningKey: keyPair.privateKey,
    trustEpoch: 0,
    baseVaultHead: previous.opRow.resultingVaultHead,
    recordType: 'item',
    vaultEncryptionKey: previous.vaultEncryptionKey,
    plaintext,
    keyVersion: 1,
    baseRecordVersion: previous.recRow.recordVersion,
    previousCiphertextHash: previous.recRow.ciphertextHash,
  });

  const opRow = toVaultOperationRow(built, { resultingVaultHead: built.resultingVaultHead });
  const recRow = toVaultRecordRow(built.sealedRecord, opRow, false);

  return { built, opRow, recRow, keyPair, vaultEncryptionKey: previous.vaultEncryptionKey, plaintext };
}

async function buildDeleteOperationAndRecord(
  previous: Awaited<ReturnType<typeof buildCreateOperationAndRecord>>,
  overrides: {
    deviceId?: string;
    keyPair?: Awaited<ReturnType<typeof generateDeviceSigningKeyPair>>;
    opId?: string;
  } = {},
) {
  const keyPair = overrides.keyPair ?? previous.keyPair;
  const deviceId = overrides.deviceId ?? previous.opRow.authorDeviceId;
  const opId = overrides.opId ?? 'op-delete-1';

  const built = await buildDeleteRecordOperation({
    opId,
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId: previous.opRow.vaultId,
    recordId: previous.recRow.recordId,
    deviceId,
    deviceSigningKey: keyPair.privateKey,
    trustEpoch: 0,
    baseVaultHead: previous.opRow.resultingVaultHead,
    recordType: 'item',
    vaultEncryptionKey: previous.vaultEncryptionKey,
    keyVersion: 1,
    baseRecordVersion: previous.recRow.recordVersion,
    previousCiphertextHash: previous.recRow.ciphertextHash,
  });

  const opRow = toVaultOperationRow(built, { resultingVaultHead: built.resultingVaultHead });
  const recRow = toVaultRecordRow(built.sealedRecord, opRow, true);

  return { built, opRow, recRow, keyPair, vaultEncryptionKey: previous.vaultEncryptionKey };
}

function buildTrust(deviceId: string, publicSigningKey: string): { vaultId: string; trustedDevicesById: Map<string, TrustedDeviceRecordV1> } {
  return {
    vaultId: 'vault-1',
    trustedDevicesById: new Map([
      [
        deviceId,
        {
          vaultId: 'vault-1',
          deviceId,
          publicSigningKey,
          deviceNameEncrypted: 'enc:name',
          addedByDeviceId: null,
          addedAt: '2026-01-01T00:00:00.000Z',
          trustEpoch: 0,
          status: 'trusted' as const,
          revokedAt: null,
          revokedByDeviceId: null,
        },
      ],
    ]),
  };
}

function emptyState(): LocalVaultState {
  return {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map(),
    lastVerifiedVaultHead: null,
  };
}

// ---------------------------------------------------------------------------
// Vault security mode tests
// ---------------------------------------------------------------------------

describe('determineVaultSecurityMode', () => {
  it('returns normal when the state is empty', () => {
    expect(determineVaultSecurityMode(emptyState())).toBe('normal');
  });

  it('returns restricted when a single record is quarantined', () => {
    const state: LocalVaultState = {
      ...emptyState(),
      quarantinedRecordsById: new Map([
        ['r1', { record: null, recordState: 'quarantinedTampered', reason: '' }],
      ]),
    };
    expect(determineVaultSecurityMode(state)).toBe('restricted');
  });

  it('returns restricted when a single conflict exists', () => {
    const state: LocalVaultState = {
      ...emptyState(),
      conflictsByRecordId: new Map([
        ['r1', { recordId: 'r1', operations: [], recordVersions: [] }],
      ]),
    };
    expect(determineVaultSecurityMode(state)).toBe('restricted');
  });

  it('returns safeModeRecommended when many records are missing without delete', () => {
    const state: LocalVaultState = {
      ...emptyState(),
      quarantinedRecordsById: new Map([
        ['r1', { record: null, recordState: 'quarantinedMissingWithoutDelete', reason: '' }],
        ['r2', { record: null, recordState: 'quarantinedMissingWithoutDelete', reason: '' }],
        ['r3', { record: null, recordState: 'quarantinedMissingWithoutDelete', reason: '' }],
      ]),
    };
    expect(determineVaultSecurityMode(state)).toBe('safeModeRecommended');
  });

  it('returns safeModeRecommended when many records are quarantined', () => {
    const quarantined = new Map<string, { record: null; recordState: 'quarantinedTampered'; reason: string }>();
    for (let i = 0; i < 5; i += 1) {
      quarantined.set(`r${i}`, { record: null, recordState: 'quarantinedTampered', reason: '' });
    }
    const state: LocalVaultState = { ...emptyState(), quarantinedRecordsById: quarantined };
    expect(determineVaultSecurityMode(state)).toBe('safeModeRecommended');
  });
});

// ---------------------------------------------------------------------------
// Decrypt gate tests — prove that decrypt is never called on negative cases
// ---------------------------------------------------------------------------

describe('applyRemoteOperation — decrypt gate', () => {
  it('calls openRecord only when operation and context are fully verified', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: recRow,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('verified');
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does NOT call openRecord when the author is unknown', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    // Empty trust list → unknown author
    const trust = { vaultId: 'vault-1', trustedDevicesById: new Map<string, TrustedDeviceRecordV1>() };

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: recRow,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedUnknownAuthor');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does NOT call openRecord when the signature is invalid', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);
    // Use a different public key so the signature cannot verify
    const wrongKeyPair = await generateDeviceSigningKeyPair();
    const wrongPublicKey = await importDevicePublicKey(wrongKeyPair.publicKeyB64Url);

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: recRow,
      trust,
      publicKey: wrongPublicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does NOT call openRecord when the AAD hash mismatches', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);

    const tamperedRec = { ...recRow, aadHash: 'tampered-aad-hash' };

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: tamperedRec,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does NOT call openRecord when the ciphertext hash mismatches', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);

    const tamperedRec = { ...recRow, ciphertextHash: 'tampered-ct-hash' };

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: tamperedRec,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('does NOT call openRecord when lastOpId does not match the operation', async () => {
    const spy = vi.spyOn(cryptoRecordService, 'openRecord');

    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);

    const tamperedRec = { ...recRow, lastOpId: 'different-op-id' };

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: tamperedRec,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// Conflict tests
// ---------------------------------------------------------------------------

describe('applyRemoteOperation — conflict handling', () => {
  it('classifies two concurrent updates as conflict, not quarantine', async () => {
    const created = await buildCreateOperationAndRecord();
    const publicKey = await importDevicePublicKey(created.keyPair.publicKeyB64Url);
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    // Apply the create
    const stateAfterCreate = await applyRemoteOperation({
      state: emptyState(),
      operation: created.opRow,
      record: created.recRow,
      trust,
      publicKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });
    expect(stateAfterCreate.recordState).toBe('verified');

    // Device A updates to version 2
    const updateA = await buildUpdateOperationAndRecord(created, {
      opId: 'op-update-a',
    });
    const stateAfterUpdateA = await applyRemoteOperation({
      state: stateAfterCreate.nextState,
      operation: updateA.opRow,
      record: updateA.recRow,
      trust,
      publicKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });
    expect(stateAfterUpdateA.recordState).toBe('verified');

    // Device B concurrently updates, still basing on version 1
    const secondKeyPair = await generateDeviceSigningKeyPair();
    const secondTrust = buildTrust('device-2', secondKeyPair.publicKeyB64Url);
    const stateWithSecondDevice: LocalVaultState = {
      ...stateAfterUpdateA.nextState,
      trustedDevicesById: new Map([
        ...stateAfterUpdateA.nextState.trustedDevicesById,
        ['device-2', {
          vaultId: 'vault-1',
          deviceId: 'device-2',
          publicSigningKey: secondKeyPair.publicKeyB64Url,
          deviceNameEncrypted: 'enc:name2',
          addedByDeviceId: 'device-1',
          addedAt: '2026-01-02T00:00:00.000Z',
          trustEpoch: 0,
          status: 'trusted' as const,
          revokedAt: null,
          revokedByDeviceId: null,
        }],
      ]),
    };

    // Device B's update bases on version 1 (the original create)
    const updateB = await buildUpdateOperationAndRecord(created, {
      keyPair: secondKeyPair,
      deviceId: 'device-2',
      opId: 'op-update-b',
    });
    const secondPublicKey = await importDevicePublicKey(secondKeyPair.publicKeyB64Url);

    const result = await applyRemoteOperation({
      state: stateWithSecondDevice,
      operation: updateB.opRow,
      record: updateB.recRow,
      trust: secondTrust,
      publicKey: secondPublicKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    // Local record is version 2; incoming update bases on version 1 → conflict
    expect(result.recordState).toBe('conflict');
    expect(result.vaultMode).toBe('restricted');
    expect(result.vaultMode).not.toBe('lockedCritical');
    expect(result.vaultMode).not.toBe('safeMode');
    expect(result.vaultMode).not.toBe('safeModeRecommended');
  });
});

// ---------------------------------------------------------------------------
// Trusted delete tests
// ---------------------------------------------------------------------------

describe('applyTrustedDelete', () => {
  it('marks a record as deletedByTrustedDevice when the delete operation is fully valid', async () => {
    const created = await buildCreateOperationAndRecord();
    const deleted = await buildDeleteOperationAndRecord(created);
    const publicKey = await importDevicePublicKey(created.keyPair.publicKeyB64Url);
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    // First apply the create
    const stateAfterCreate = await applyRemoteOperation({
      state: emptyState(),
      operation: created.opRow,
      record: created.recRow,
      trust,
      publicKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });
    expect(stateAfterCreate.recordState).toBe('verified');

    // Then apply the delete
    const result = await applyTrustedDelete({
      state: stateAfterCreate.nextState,
      operation: deleted.opRow,
      record: deleted.recRow,
      trust,
      publicKey,
    });

    expect(result.recordState).toBe('deletedByTrustedDevice');
    expect(result.vaultMode).toBe('normal');
  });

  it('treats a valid signed delete as deleted when the server returns a stale active record row', async () => {
    const created = await buildCreateOperationAndRecord();
    const deleted = await buildDeleteOperationAndRecord(created);
    const publicKey = await importDevicePublicKey(created.keyPair.publicKeyB64Url);
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const stateAfterCreate = await applyRemoteOperation({
      state: emptyState(),
      operation: created.opRow,
      record: created.recRow,
      trust,
      publicKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });
    expect(stateAfterCreate.recordState).toBe('verified');

    const staleActiveRecord = {
      ...created.recRow,
      lastOpId: deleted.opRow.opId,
      lastOpHash: deleted.opRow.opHash,
      isTombstone: false,
    };

    const result = await applyTrustedDelete({
      state: stateAfterCreate.nextState,
      operation: deleted.opRow,
      record: staleActiveRecord,
      trust,
      publicKey,
    });

    expect(result.recordState).toBe('deletedByTrustedDevice');
    expect(result.vaultMode).toBe('normal');
    expect(result.nextState.quarantinedRecordsById.has(staleActiveRecord.recordId)).toBe(false);
  });

  it('does not accept a delete with an invalid signature', async () => {
    const created = await buildCreateOperationAndRecord();
    const deleted = await buildDeleteOperationAndRecord(created);
    // Use a different public key so the signature cannot verify
    const wrongKeyPair = await generateDeviceSigningKeyPair();
    const wrongPublicKey = await importDevicePublicKey(wrongKeyPair.publicKeyB64Url);
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const result = await applyTrustedDelete({
      state: emptyState(),
      operation: deleted.opRow,
      record: deleted.recRow,
      trust,
      publicKey: wrongPublicKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
  });
});

// ---------------------------------------------------------------------------
// Category / container quarantine tests (isolated, not vault-critical)
// ---------------------------------------------------------------------------

describe('applyRemoteOperation — category handling', () => {
  it('does not set lockedCritical when a single category record is quarantined', async () => {
    const { opRow, recRow, keyPair, vaultEncryptionKey } = await buildCreateOperationAndRecord({
      recordType: 'category',
      plaintext: makePlaintext({ name: 'Test Category' }),
    });
    const publicKey = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const trust = buildTrust(opRow.authorDeviceId, keyPair.publicKeyB64Url);

    // Tamper the record so it becomes quarantined
    const tamperedRec = { ...recRow, ciphertextHash: 'tampered-ct-hash' };

    const result = await applyRemoteOperation({
      state: emptyState(),
      operation: opRow,
      record: tamperedRec,
      trust,
      publicKey,
      vaultEncryptionKey,
    });

    expect(result.recordState).toBe('quarantinedTampered');
    expect(result.vaultMode).toBe('restricted');
    expect(result.vaultMode).not.toBe('lockedCritical');
  });
});
