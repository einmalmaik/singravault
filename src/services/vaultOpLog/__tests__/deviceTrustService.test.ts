// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  applyDeviceTrustOperation,
  classifyOperationAuthor,
} from '../deviceTrustService';
import {
  buildOperationSignedBody,
  signOperation,
  generateDeviceSigningKeyPair,
} from '../operationSigningService';
import { VaultSignatureError, type TrustedDeviceRecordV1 } from '../types';

function buildTrustedDevice(overrides: Partial<TrustedDeviceRecordV1> = {}): TrustedDeviceRecordV1 {
  return {
    vaultId: 'v1',
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

async function signedOperationForDevice(deviceId: string, overrides: {
  vaultId?: string;
  trustEpoch?: number;
  createdAtClient?: string;
  opId?: string;
  opType?: 'create' | 'update' | 'add_device' | 'revoke_device';
} = {}) {
  const keyPair = await generateDeviceSigningKeyPair();
  const body = buildOperationSignedBody({
    opId: overrides.opId ?? 'op-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId: overrides.vaultId ?? 'v1',
    authorDeviceId: deviceId,
    opType: overrides.opType ?? 'create',
    recordId: 'rec-1',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'new-hash',
    baseVaultHead: null,
    payloadCiphertextHash: 'ct-hash',
    payloadAadHash: 'aad-hash',
    createdAtClient: overrides.createdAtClient ?? '2026-05-01T10:00:00.000Z',
    trustEpoch: overrides.trustEpoch ?? 0,
  });
  return signOperation(body, keyPair.privateKey);
}

describe('classifyOperationAuthor', () => {
  it('returns trusted when the device is on the trust list and epochs match', async () => {
    const op = await signedOperationForDevice('device-1');
    const trust = new Map([[
      'device-1',
      buildTrustedDevice(),
    ]]);
    expect(classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust }).status).toBe(
      'trusted',
    );
  });

  it('returns unknown when the device is not on the trust list', async () => {
    const op = await signedOperationForDevice('unknown-device');
    const trust = new Map([[
      'device-1',
      buildTrustedDevice(),
    ]]);
    expect(classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust })).toEqual({
      status: 'unknown',
      reason: 'device_not_in_trust_list',
    });
  });

  it('returns unknown when the op vaultId does not match the trust list vaultId', async () => {
    const op = await signedOperationForDevice('device-1', { vaultId: 'v2' });
    const trust = new Map([[
      'device-1',
      buildTrustedDevice(),
    ]]);
    expect(classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust })).toEqual({
      status: 'unknown',
      reason: 'device_wrong_vault',
    });
  });

  it('returns unknown when trust epoch differs', async () => {
    const op = await signedOperationForDevice('device-1', { trustEpoch: 1 });
    const trust = new Map([[
      'device-1',
      buildTrustedDevice({ trustEpoch: 0 }),
    ]]);
    expect(classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust })).toEqual({
      status: 'unknown',
      reason: 'device_trust_epoch_mismatch',
    });
  });

  it('returns revoked when device was revoked before the op', async () => {
    const op = await signedOperationForDevice('device-1', {
      createdAtClient: '2026-05-02T10:00:00.000Z',
    });
    const trust = new Map([[
      'device-1',
      buildTrustedDevice({
        status: 'revoked',
        revokedAt: '2026-05-01T10:00:00.000Z',
      }),
    ]]);
    const result = classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust });
    expect(result.status).toBe('revoked');
  });

  it('still returns revoked even if op was authored before revocation (conservative policy)', async () => {
    const op = await signedOperationForDevice('device-1', {
      createdAtClient: '2026-05-01T10:00:00.000Z',
    });
    const trust = new Map([[
      'device-1',
      buildTrustedDevice({
        status: 'revoked',
        revokedAt: '2026-05-02T10:00:00.000Z',
      }),
    ]]);
    expect(classifyOperationAuthor(op, { vaultId: 'v1', trustedDevicesById: trust }).status).toBe(
      'revoked',
    );
  });
});

describe('applyDeviceTrustOperation', () => {
  it('adds a new device on add_device', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'add_device' });
    const trust = new Map<string, TrustedDeviceRecordV1>();
    const newDevice = buildTrustedDevice({ deviceId: 'new-device' });
    const next = applyDeviceTrustOperation(trust, op, { kind: 'add', device: newDevice });
    expect(next.get('new-device')).toEqual(newDevice);
  });

  it('rejects add_device if device already present', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'add_device' });
    const trust = new Map([['dupe', buildTrustedDevice({ deviceId: 'dupe' })]]);
    expect(() =>
      applyDeviceTrustOperation(trust, op, {
        kind: 'add',
        device: buildTrustedDevice({ deviceId: 'dupe' }),
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects add_device if device is for another vault', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'add_device' });
    expect(() =>
      applyDeviceTrustOperation(new Map(), op, {
        kind: 'add',
        device: buildTrustedDevice({ vaultId: 'other-vault' }),
      }),
    ).toThrow(VaultSignatureError);
  });

  it('revokes an existing device and increments the trust epoch', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'revoke_device' });
    const existing = buildTrustedDevice({ deviceId: 'victim', trustEpoch: 2 });
    const trust = new Map([['victim', existing]]);
    const next = applyDeviceTrustOperation(trust, op, {
      kind: 'revoke',
      deviceId: 'victim',
      revokedAt: '2026-05-02T10:00:00.000Z',
    });
    const revoked = next.get('victim');
    expect(revoked?.status).toBe('revoked');
    expect(revoked?.revokedAt).toBe('2026-05-02T10:00:00.000Z');
    expect(revoked?.trustEpoch).toBe(3);
    expect(revoked?.revokedByDeviceId).toBe('authoriser');
  });

  it('rejects revoke_device for an unknown device', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'revoke_device' });
    expect(() =>
      applyDeviceTrustOperation(new Map(), op, {
        kind: 'revoke',
        deviceId: 'nobody',
        revokedAt: '2026-05-02T10:00:00.000Z',
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects mismatched op type and payload kind', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'add_device' });
    expect(() =>
      applyDeviceTrustOperation(new Map(), op, {
        kind: 'revoke',
        deviceId: 'x',
        revokedAt: '2026-05-02T10:00:00.000Z',
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects non-device-trust op types', async () => {
    const op = await signedOperationForDevice('authoriser', { opType: 'update' });
    expect(() =>
      applyDeviceTrustOperation(new Map(), op, {
        kind: 'add',
        device: buildTrustedDevice({ deviceId: 'x' }),
      }),
    ).toThrow(VaultSignatureError);
  });
});
