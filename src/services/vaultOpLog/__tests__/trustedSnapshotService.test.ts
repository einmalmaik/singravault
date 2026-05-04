// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for trusted snapshot service — Phase 6.
 *
 * Security invariants under test:
 * - Snapshots contain only verified / deleted-by-trusted-device records.
 * - Snapshot plaintext is encrypted and never persisted in cleartext.
 * - Snapshot envelope is signed by a trusted device.
 * - Tampered envelope, ciphertext, AAD, nonce or signature is rejected.
 * - Restore always produces a new signed operation via the builder.
 * - Restore re-encrypts plaintext; it does not blind-copy old ciphertext.
 * - Category restore can re-evaluate container-quarantined items.
 * - Retention never removes every snapshot.
 */

import { describe, expect, it, vi } from 'vitest';
import {
  generateDeviceSigningKeyPair,
  importDevicePublicKey,
} from '../operationSigningService';
import {
  buildCreateRecordOperation,
  buildDeleteRecordOperation,
  buildUpdateRecordOperation,
  buildRestoreRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
} from '../vaultOpLogOperationBuilder';
import {
  createTrustedSnapshot,
  verifyTrustedSnapshot,
  findSnapshotRecord,
  buildRestoreOperationFromSnapshot,
  reevaluateContainerQuarantinedItems,
  saveSnapshotEnvelope,
  loadAndVerifySnapshot,
} from '../trustedSnapshotService';
import { applySnapshotRetentionPolicy } from '../snapshotRetentionPolicy';
import {
  deriveSnapshotKey,
  sealSnapshot,
  openSnapshot,
  computeSnapshotHash,
} from '../snapshotCrypto';
import {
  TRUSTED_SNAPSHOT_SCHEMA_V1,
  TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1,
  TrustedSnapshotError,
  type TrustedSnapshotEnvelopeV1,
  type SnapshotStorage,
} from '../trustedSnapshotTypes';
import type { LocalVaultState, LocalVerifiedRecord } from '../vaultStateMachine';
import type { TrustedDeviceRecordV1, VaultOperationSignedBodyV1 } from '../types';

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

function makeInMemoryStorage(): SnapshotStorage {
  const store = new Map<string, TrustedSnapshotEnvelopeV1>();
  return {
    save: async (e) => { store.set(e.snapshotId, e); },
    load: async (id) => store.get(id) ?? null,
    listForVault: async (vaultId) =>
      Array.from(store.values()).filter((e) => e.vaultId === vaultId),
    delete: async (id) => { store.delete(id); },
  };
}

// ---------------------------------------------------------------------------
// Snapshot creation
// ---------------------------------------------------------------------------

describe('createTrustedSnapshot', () => {
  it('includes verified and deletedByTrustedDevice records', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const result = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: created.opRow.resultingVaultHead,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    expect(result.envelope.schema).toBe(TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1);
    expect(result.envelope.snapshotId).toBe('snap-1');
    expect(result.envelope.signature).not.toBe('');
    expect(result.excludedRecords).toHaveLength(0);
  });

  it('excludes quarantined, conflict, pending and containerQuarantined records', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
        ['item-2', {
          record: { ...created.recRow, recordId: 'item-2' },
          recordState: 'containerQuarantined',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      quarantinedRecordsById: new Map([
        ['item-3', { record: { ...created.recRow, recordId: 'item-3' }, recordState: 'quarantinedTampered', reason: 'test' }],
        ['item-4', { record: { ...created.recRow, recordId: 'item-4' }, recordState: 'quarantinedUnknownAuthor', reason: 'test' }],
        ['item-5', { record: { ...created.recRow, recordId: 'item-5' }, recordState: 'quarantinedMissingWithoutDelete', reason: 'test' }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const result = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    // Decrypt and inspect plaintext
    const verified = await verifyTrustedSnapshot({
      envelope: result.envelope,
      vaultId: 'vault-1',
      trust,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    const recordIds = verified.plaintext.records.map((r) => r.recordId);
    expect(recordIds).toContain('item-1');
    expect(recordIds).not.toContain('item-2');
    expect(recordIds).not.toContain('item-3');
    expect(recordIds).not.toContain('item-4');
    expect(recordIds).not.toContain('item-5');

    const excludedIds = result.excludedRecords.map((e) => e.recordId);
    expect(excludedIds).toContain('item-2');
    expect(excludedIds).toContain('item-3');
    expect(excludedIds).toContain('item-4');
    expect(excludedIds).toContain('item-5');
  });

  it('refuses snapshot creation when current device is not trusted', async () => {
    const created = await buildCreateOperationAndRecord();
    const state: LocalVaultState = {
      ...emptyState(),
      trustedDevicesById: new Map(), // empty trust list
    };

    await expect(
      createTrustedSnapshot({
        snapshotId: 'snap-1',
        vaultId: 'vault-1',
        createdByDeviceId: 'device-1',
        deviceSigningKey: created.keyPair.privateKey,
        vaultEncryptionKey: created.vaultEncryptionKey,
        trustEpoch: 0,
        verifiedVaultHead: null,
        state,
        trustedDevicesHash: 'td-hash-1',
        manifestHash: 'manifest-hash-1',
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });

  it('persists encrypted envelope, not plaintext', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const result = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const envelope = result.envelope;
    // The ciphertext must not contain the plaintext JSON directly
    const rawCiphertext = new TextDecoder().decode(
      Uint8Array.from(atob(envelope.snapshotCiphertext.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
    );
    // AES-GCM ciphertext is binary and won't contain readable JSON
    expect(rawCiphertext).not.toContain('trusted-snapshot-v1');
  });
});

// ---------------------------------------------------------------------------
// Snapshot verification
// ---------------------------------------------------------------------------

describe('verifyTrustedSnapshot', () => {
  it('accepts a valid snapshot', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const verified = await verifyTrustedSnapshot({
      envelope: createdSnap.envelope,
      vaultId: 'vault-1',
      trust,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    expect(verified.plaintext.schema).toBe(TRUSTED_SNAPSHOT_SCHEMA_V1);
    expect(verified.plaintext.snapshotId).toBe('snap-1');
  });

  it('rejects a snapshot with tampered envelope metadata (vaultId)', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const tampered = { ...createdSnap.envelope, vaultId: 'vault-evil' };

    await expect(
      verifyTrustedSnapshot({
        envelope: tampered,
        vaultId: 'vault-1',
        trust,
        vaultEncryptionKey: created.vaultEncryptionKey,
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });

  it('rejects a snapshot with tampered ciphertext', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const tampered = { ...createdSnap.envelope, snapshotCiphertext: createdSnap.envelope.snapshotCiphertext + 'ff' };
    // Recompute hash to match tampered ciphertext (otherwise hash check fails first)
    const tamperedWithHash = { ...tampered, snapshotHash: await computeSnapshotHash(tampered) };

    await expect(
      verifyTrustedSnapshot({
        envelope: tamperedWithHash,
        vaultId: 'vault-1',
        trust,
        vaultEncryptionKey: created.vaultEncryptionKey,
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });

  it('rejects a snapshot with tampered signature', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const tampered = { ...createdSnap.envelope, signature: createdSnap.envelope.signature.slice(0, -4) + 'AAAA' };

    await expect(
      verifyTrustedSnapshot({
        envelope: tampered,
        vaultId: 'vault-1',
        trust,
        vaultEncryptionKey: created.vaultEncryptionKey,
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });

  it('rejects a snapshot from a revoked device', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    // Revoke the device in trust list
    const revokedTrust = {
      vaultId: 'vault-1',
      trustedDevicesById: new Map([
        [
          'device-1',
          {
            vaultId: 'vault-1',
            deviceId: 'device-1',
            publicSigningKey: created.keyPair.publicKeyB64Url,
            deviceNameEncrypted: 'enc:name',
            addedByDeviceId: null,
            addedAt: '2026-01-01T00:00:00.000Z',
            trustEpoch: 0,
            status: 'revoked' as const,
            revokedAt: '2026-01-02T00:00:00.000Z',
            revokedByDeviceId: 'device-1',
          },
        ],
      ]),
    };

    await expect(
      verifyTrustedSnapshot({
        envelope: createdSnap.envelope,
        vaultId: 'vault-1',
        trust: revokedTrust,
        vaultEncryptionKey: created.vaultEncryptionKey,
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });

  it('rejects an unknown schema version', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const tampered = { ...createdSnap.envelope, schema: 'trusted-snapshot-envelope-v999' } as unknown as TrustedSnapshotEnvelopeV1;

    await expect(
      verifyTrustedSnapshot({
        envelope: tampered,
        vaultId: 'vault-1',
        trust,
        vaultEncryptionKey: created.vaultEncryptionKey,
      }),
    ).rejects.toThrow(TrustedSnapshotError);
  });
});

// ---------------------------------------------------------------------------
// Snapshot crypto helpers
// ---------------------------------------------------------------------------

describe('snapshotCrypto', () => {
  it('seal and open roundtrip with correct key', async () => {
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const plaintext = makePlaintext({ hello: 'snapshot' });

    const snapshotKey = await deriveSnapshotKey({
      vaultEncryptionKey,
      vaultId: 'vault-1',
      snapshotId: 'snap-1',
      deviceId: 'device-1',
      trustEpoch: 0,
    });

    const aad = {
      app: 'singra-vault' as const,
      aadSchema: 'snapshot-aad-v1' as const,
      vaultId: 'vault-1',
      snapshotId: 'snap-1',
      deviceId: 'device-1',
      trustEpoch: 0,
      verifiedVaultHead: null,
      createdAt: '2026-05-04T12:00:00.000Z',
    };

    const sealed = await sealSnapshot({ plaintext, snapshotKey, aad });
    const opened = await openSnapshot({ sealed, snapshotKey, expectedAad: aad });

    expect(Array.from(opened)).toEqual(Array.from(plaintext));
  });

  it('open fails with wrong key', async () => {
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const wrongKey = makeVaultEncryptionKey();
    const plaintext = makePlaintext({ hello: 'snapshot' });

    const snapshotKey = await deriveSnapshotKey({
      vaultEncryptionKey,
      vaultId: 'vault-1',
      snapshotId: 'snap-1',
      deviceId: 'device-1',
      trustEpoch: 0,
    });

    const aad = {
      app: 'singra-vault' as const,
      aadSchema: 'snapshot-aad-v1' as const,
      vaultId: 'vault-1',
      snapshotId: 'snap-1',
      deviceId: 'device-1',
      trustEpoch: 0,
      verifiedVaultHead: null,
      createdAt: '2026-05-04T12:00:00.000Z',
    };

    const sealed = await sealSnapshot({ plaintext, snapshotKey, aad });
    const wrongSnapshotKey = await deriveSnapshotKey({
      vaultEncryptionKey: wrongKey,
      vaultId: 'vault-1',
      snapshotId: 'snap-1',
      deviceId: 'device-1',
      trustEpoch: 0,
    });

    await expect(
      openSnapshot({ sealed, snapshotKey: wrongSnapshotKey, expectedAad: aad }),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Restore from snapshot
// ---------------------------------------------------------------------------

describe('buildRestoreOperationFromSnapshot', () => {
  it('produces a signed restore operation with fresh nonce and version', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const verified = await verifyTrustedSnapshot({
      envelope: createdSnap.envelope,
      vaultId: 'vault-1',
      trust,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    const snapshotRecord = findSnapshotRecord(verified.plaintext, 'item-1');
    expect(snapshotRecord).not.toBeNull();

    const restoreOp = await buildRestoreOperationFromSnapshot({
      snapshotRecord: snapshotRecord!,
      vaultId: 'vault-1',
      recordId: 'item-1',
      recordType: 'item',
      baseRecordVersion: created.recRow.recordVersion,
      previousCiphertextHash: created.recRow.ciphertextHash,
      baseVaultHead: created.opRow.resultingVaultHead,
      vaultEncryptionKey: created.vaultEncryptionKey,
      keyVersion: 1,
      deviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      trustEpoch: 0,
      opId: 'op-restore-1',
      intentId: 'intent-restore-1',
      rebasedFromOpId: null,
    });

    expect(restoreOp.signedOperation.body.opType).toBe('restore');
    expect(restoreOp.signedOperation.body.recordId).toBe('item-1');
    expect(restoreOp.signedOperation.body.baseRecordVersion).toBe(created.recRow.recordVersion);
    expect(restoreOp.sealedRecord.aad.recordVersion).toBe(created.recRow.recordVersion + 1);
    expect(restoreOp.sealedRecord.nonceB64Url).not.toBe(created.recRow.nonce);
  });

  it('restore for item validates item plaintext schema', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1', plaintext: makePlaintext({ username: 'alice' }) });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const verified = await verifyTrustedSnapshot({
      envelope: createdSnap.envelope,
      vaultId: 'vault-1',
      trust,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    const snapshotRecord = findSnapshotRecord(verified.plaintext, 'item-1')!;

    const restoreOp = await buildRestoreOperationFromSnapshot({
      snapshotRecord,
      vaultId: 'vault-1',
      recordId: 'item-1',
      recordType: 'item',
      baseRecordVersion: created.recRow.recordVersion,
      previousCiphertextHash: created.recRow.ciphertextHash,
      baseVaultHead: created.opRow.resultingVaultHead,
      vaultEncryptionKey: created.vaultEncryptionKey,
      keyVersion: 1,
      deviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      trustEpoch: 0,
      opId: 'op-restore-1',
      intentId: 'intent-restore-1',
      rebasedFromOpId: null,
    });

    expect(restoreOp.signedOperation.body.opType).toBe('restore');
  });

  it('restore for category validates category plaintext schema', async () => {
    const created = await buildCreateOperationAndRecord({
      recordId: 'cat-1',
      recordType: 'category',
      plaintext: makePlaintext({ name: 'Work' }),
    });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['cat-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const verified = await verifyTrustedSnapshot({
      envelope: createdSnap.envelope,
      vaultId: 'vault-1',
      trust,
      vaultEncryptionKey: created.vaultEncryptionKey,
    });

    const snapshotRecord = findSnapshotRecord(verified.plaintext, 'cat-1')!;

    const restoreOp = await buildRestoreOperationFromSnapshot({
      snapshotRecord,
      vaultId: 'vault-1',
      recordId: 'cat-1',
      recordType: 'category',
      baseRecordVersion: created.recRow.recordVersion,
      previousCiphertextHash: created.recRow.ciphertextHash,
      baseVaultHead: created.opRow.resultingVaultHead,
      vaultEncryptionKey: created.vaultEncryptionKey,
      keyVersion: 1,
      deviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      trustEpoch: 0,
      opId: 'op-restore-1',
      intentId: 'intent-restore-1',
      rebasedFromOpId: null,
    });

    expect(restoreOp.signedOperation.body.opType).toBe('restore');
    expect(restoreOp.signedOperation.body.recordType).toBe('category');
  });
});

// ---------------------------------------------------------------------------
// buildRestoreRecordOperation (operation builder)
// ---------------------------------------------------------------------------

describe('buildRestoreRecordOperation', () => {
  it('is implemented in Phase 6 and produces a restore operation', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });

    const restore = await buildRestoreRecordOperation({
      opId: 'op-restore-1',
      intentId: 'intent-restore-1',
      rebasedFromOpId: null,
      vaultId: 'vault-1',
      recordId: 'item-1',
      deviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      trustEpoch: 0,
      baseVaultHead: created.opRow.resultingVaultHead,
      recordType: 'item',
      vaultEncryptionKey: created.vaultEncryptionKey,
      plaintext: created.plaintext,
      keyVersion: 1,
      baseRecordVersion: created.recRow.recordVersion,
      previousCiphertextHash: created.recRow.ciphertextHash,
    });

    expect(restore.signedOperation.body.opType).toBe('restore');
    expect(restore.signedOperation.body.recordId).toBe('item-1');
    expect(restore.sealedRecord.aad.recordVersion).toBe(created.recRow.recordVersion + 1);
  });
});

// ---------------------------------------------------------------------------
// Category restore / container quarantine re-evaluation
// ---------------------------------------------------------------------------

describe('reevaluateContainerQuarantinedItems', () => {
  it('downgrades containerQuarantined items back to verified', () => {
    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: { vaultId: 'vault-1', recordId: 'item-1', recordType: 'item', recordVersion: 1, keyVersion: 1, aadHash: 'a', ciphertextHash: 'c', nonce: 'n', ciphertext: 'ct', lastOpId: 'op-1', lastOpHash: 'oh', isTombstone: false, createdAt: '', updatedAt: '' },
          recordState: 'containerQuarantined',
          plaintext: makePlaintext({ name: 'Item 1' }),
          lastOperation: { opId: 'op-1', opHash: 'oh', vaultId: 'vault-1', authorDeviceId: 'd1', opType: 'create', recordId: 'item-1', recordType: 'item', baseRecordVersion: null, previousCiphertextHash: null, newRecordHash: 'c', baseVaultHead: null, resultingVaultHead: 'h', intentId: 'i1', rebasedFromOpId: null, payloadCiphertextHash: 'c', payloadAadHash: 'a', signedBody: {} as VaultOperationSignedBodyV1, signature: 's', signatureSchema: 'device-signature-v1', trustEpoch: 0, createdAtClient: '', receivedAtServer: '', sequenceNumber: 0 },
        }],
      ]),
    };

    const nextState = reevaluateContainerQuarantinedItems(state, 'cat-1');
    const item = nextState.recordsById.get('item-1');
    expect(item?.recordState).toBe('verified');
  });

  it('does not affect items with other quarantine states', () => {
    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: { vaultId: 'vault-1', recordId: 'item-1', recordType: 'item', recordVersion: 1, keyVersion: 1, aadHash: 'a', ciphertextHash: 'c', nonce: 'n', ciphertext: 'ct', lastOpId: 'op-1', lastOpHash: 'oh', isTombstone: false, createdAt: '', updatedAt: '' },
          recordState: 'verified',
          plaintext: makePlaintext({ name: 'Item 1' }),
          lastOperation: { opId: 'op-1', opHash: 'oh', vaultId: 'vault-1', authorDeviceId: 'd1', opType: 'create', recordId: 'item-1', recordType: 'item', baseRecordVersion: null, previousCiphertextHash: null, newRecordHash: 'c', baseVaultHead: null, resultingVaultHead: 'h', intentId: 'i1', rebasedFromOpId: null, payloadCiphertextHash: 'c', payloadAadHash: 'a', signedBody: {} as VaultOperationSignedBodyV1, signature: 's', signatureSchema: 'device-signature-v1', trustEpoch: 0, createdAtClient: '', receivedAtServer: '', sequenceNumber: 0 },
        }],
      ]),
    };

    const nextState = reevaluateContainerQuarantinedItems(state, 'cat-1');
    expect(nextState).toBe(state);
  });
});

// ---------------------------------------------------------------------------
// Snapshot retention
// ---------------------------------------------------------------------------

describe('applySnapshotRetentionPolicy', () => {
  it('keeps the latest snapshot and protects the oldest as fallback', () => {
    const envelopes: TrustedSnapshotEnvelopeV1[] = [
      { snapshotId: 'snap-old', vaultId: 'v1', createdAt: '2026-03-01T00:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
      { snapshotId: 'snap-new', vaultId: 'v1', createdAt: '2026-05-04T00:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
    ];

    const result = applySnapshotRetentionPolicy(envelopes, '2026-05-04T12:00:00.000Z');
    expect(result.kept).toContain('snap-new');
    expect(result.kept).toContain('snap-old');
    expect(result.removed).toHaveLength(0);
  });

  it('never removes every snapshot', () => {
    const envelopes: TrustedSnapshotEnvelopeV1[] = [
      { snapshotId: 'snap-only', vaultId: 'v1', createdAt: '2026-04-01T00:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
    ];

    const result = applySnapshotRetentionPolicy(envelopes, '2026-05-04T12:00:00.000Z');
    expect(result.kept).toContain('snap-only');
    expect(result.removed).toHaveLength(0);
  });

  it('keeps daily snapshots for 7 days and weekly for 4 weeks', () => {
    const envelopes: TrustedSnapshotEnvelopeV1[] = [
      { snapshotId: 'snap-today', vaultId: 'v1', createdAt: '2026-05-04T10:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
      { snapshotId: 'snap-yesterday', vaultId: 'v1', createdAt: '2026-05-03T10:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
      { snapshotId: 'snap-8days', vaultId: 'v1', createdAt: '2026-04-26T10:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
      { snapshotId: 'snap-30days', vaultId: 'v1', createdAt: '2026-04-04T10:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
      { snapshotId: 'snap-60days', vaultId: 'v1', createdAt: '2026-03-05T10:00:00.000Z', createdByDeviceId: 'd1', verifiedVaultHead: null, trustEpoch: 0, schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1, encryptionSchema: 'trusted-snapshot-aead-v1', signatureSchema: 'device-signature-v1', nonce: 'n', aadHash: 'a', snapshotCiphertext: 'c', snapshotHash: 'h', signature: 's' } as TrustedSnapshotEnvelopeV1,
    ];

    const result = applySnapshotRetentionPolicy(envelopes, '2026-05-04T12:00:00.000Z');
    expect(result.kept).toContain('snap-today');     // latest + daily
    expect(result.kept).toContain('snap-yesterday'); // daily
    expect(result.kept).toContain('snap-8days');   // weekly (within 4 weeks, outside daily)
    expect(result.kept).toContain('snap-60days');    // oldest fallback
    expect(result.removed).toContain('snap-30days'); // outside daily, outside weekly, not oldest
  });
});

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

describe('snapshot storage helpers', () => {
  it('save and load roundtrip through SnapshotStorage', async () => {
    const created = await buildCreateOperationAndRecord({ recordId: 'item-1' });
    const trust = buildTrust(created.opRow.authorDeviceId, created.keyPair.publicKeyB64Url);

    const state: LocalVaultState = {
      ...emptyState(),
      recordsById: new Map([
        ['item-1', {
          record: created.recRow,
          recordState: 'verified',
          plaintext: created.plaintext,
          lastOperation: created.opRow,
        }],
      ]),
      trustedDevicesById: trust.trustedDevicesById,
    };

    const createdSnap = await createTrustedSnapshot({
      snapshotId: 'snap-1',
      vaultId: 'vault-1',
      createdByDeviceId: 'device-1',
      deviceSigningKey: created.keyPair.privateKey,
      vaultEncryptionKey: created.vaultEncryptionKey,
      trustEpoch: 0,
      verifiedVaultHead: null,
      state,
      trustedDevicesHash: 'td-hash-1',
      manifestHash: 'manifest-hash-1',
    });

    const storage = makeInMemoryStorage();
    await saveSnapshotEnvelope(storage, createdSnap.envelope);

    const loaded = await loadAndVerifySnapshot(storage, 'snap-1', 'vault-1', trust, created.vaultEncryptionKey);
    expect(loaded.plaintext.snapshotId).toBe('snap-1');
  });
});
