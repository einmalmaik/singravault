// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import { generateDeviceSigningKeyPair } from '../operationSigningService';
import { recoverVaultOpLogDeviceIdentity } from '../vaultOpLogDeviceIdentityRecovery';
import {
  loadVerifiedVaultOpLogDeviceContext,
  recoverVaultOpLogDeviceIdentityFromOfflineCache,
} from '../vaultOpLogDeviceIdentityRecovery';
import { saveVaultOpLogDeviceSigningKey } from '../vaultOpLogDeviceSigningKeyStore';
import {
  clearVaultOpLogDeviceIdentity,
  loadVaultOpLogDeviceIdentity,
} from '../vaultOpLogDeviceStore';
import {
  loadVerifiedVaultOpLogOfflineCache,
  saveVerifiedVaultOpLogOfflineCache,
} from '../vaultOpLogOfflineStore';

function trustClient(rows: unknown[]) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: async () => ({ data: rows, error: null }),
        }),
      }),
    }),
  };
}

describe('vaultOpLogDeviceIdentityRecovery', () => {
  it('recovers identity metadata from a local signing key and trusted cloud device record', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const keyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: keyPair.privateKey,
    });
    clearVaultOpLogDeviceIdentity();

    const recovered = await recoverVaultOpLogDeviceIdentity({
      userId,
      vaultId,
      trustClient: trustClient([{
        device_id: deviceId,
        public_signing_key: keyPair.publicKeyB64Url,
        trust_epoch: 0,
        status: 'trusted',
      }]),
    });

    expect(recovered).toEqual({
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
    });
    expect(loadVaultOpLogDeviceIdentity()).toEqual(recovered);

    const rawIdentity = localStorage.getItem('singra_vault_oplog_device_identity');
    expect(rawIdentity).not.toContain('privateKey');
    expect(rawIdentity).not.toContain('deviceSigningKey');
    expect(rawIdentity).not.toContain('vaultEncryptionKey');
  });

  it('does not recover when the local signing key does not match the trusted public key', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const localKeyPair = await generateDeviceSigningKeyPair();
    const otherKeyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: localKeyPair.privateKey,
    });
    clearVaultOpLogDeviceIdentity();

    const recovered = await recoverVaultOpLogDeviceIdentity({
      userId,
      vaultId,
      trustClient: trustClient([{
        device_id: deviceId,
        public_signing_key: otherKeyPair.publicKeyB64Url,
        trust_epoch: 0,
        status: 'trusted',
      }]),
    });

    expect(recovered).toBeNull();
    expect(loadVaultOpLogDeviceIdentity()).toBeNull();
  });

  it('does not recover revoked device records', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const keyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: keyPair.privateKey,
    });
    clearVaultOpLogDeviceIdentity();

    const recovered = await recoverVaultOpLogDeviceIdentity({
      userId,
      vaultId,
      trustClient: trustClient([{
        device_id: deviceId,
        public_signing_key: keyPair.publicKeyB64Url,
        trust_epoch: 0,
        status: 'revoked',
      }]),
    });

    expect(recovered).toBeNull();
  });

  it('loads the trust epoch from the trusted device record for CRUD signing', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const keyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: keyPair.privateKey,
    });
    clearVaultOpLogDeviceIdentity();

    const context = await loadVerifiedVaultOpLogDeviceContext({
      userId,
      vaultId,
      trustClient: trustClient([{
        device_id: deviceId,
        public_signing_key: keyPair.publicKeyB64Url,
        trust_epoch: 3,
        status: 'trusted',
      }]),
    });

    expect(context).toEqual({
      identity: {
        deviceId,
        publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      },
      trustEpoch: 3,
    });
  });

  it('recovers identity metadata offline from a verified OpLog cache and matching local signing key', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const keyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: keyPair.privateKey,
    });
    await saveVerifiedVaultOpLogOfflineCache({
      userId,
      vaultId,
      currentHead: null,
      currentSequenceNumber: 0,
      operations: [],
      records: [],
      trustedDevices: [{
        vaultId,
        deviceId,
        publicSigningKey: keyPair.publicKeyB64Url,
        deviceNameEncrypted: 'synthetic-test-device-name',
        addedByDeviceId: null,
        addedOpId: null,
        addedAt: new Date(0).toISOString(),
        trustEpoch: 0,
        status: 'trusted',
        revokedAt: null,
        revokedByDeviceId: null,
      }],
    });
    clearVaultOpLogDeviceIdentity();

    await expect(loadVerifiedVaultOpLogOfflineCache({ userId, vaultId })).resolves.toMatchObject({
      vaultId,
      trustedDevices: [{
        deviceId,
        publicSigningKey: keyPair.publicKeyB64Url,
        status: 'trusted',
      }],
    });

    const recovered = await recoverVaultOpLogDeviceIdentityFromOfflineCache({
      userId,
      vaultId,
    });

    expect(recovered).toEqual({
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
    });
    expect(loadVaultOpLogDeviceIdentity()).toEqual(recovered);
  });

  it('does not recover identity metadata offline for revoked cached devices', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const keyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: keyPair.privateKey,
    });
    await saveVerifiedVaultOpLogOfflineCache({
      userId,
      vaultId,
      currentHead: null,
      currentSequenceNumber: 0,
      operations: [],
      records: [],
      trustedDevices: [{
        vaultId,
        deviceId,
        publicSigningKey: keyPair.publicKeyB64Url,
        deviceNameEncrypted: 'synthetic-test-device-name',
        addedByDeviceId: null,
        addedOpId: null,
        addedAt: new Date(0).toISOString(),
        trustEpoch: 0,
        status: 'revoked',
        revokedAt: new Date(1).toISOString(),
        revokedByDeviceId: `device-${crypto.randomUUID()}`,
      }],
    });
    clearVaultOpLogDeviceIdentity();

    await expect(recoverVaultOpLogDeviceIdentityFromOfflineCache({
      userId,
      vaultId,
    })).resolves.toBeNull();
    expect(loadVaultOpLogDeviceIdentity()).toBeNull();
  });

  it('does not recover identity metadata offline when the local signing key mismatches the cached public key', async () => {
    const userId = `user-${crypto.randomUUID()}`;
    const vaultId = `vault-${crypto.randomUUID()}`;
    const deviceId = `device-${crypto.randomUUID()}`;
    const localKeyPair = await generateDeviceSigningKeyPair();
    const otherKeyPair = await generateDeviceSigningKeyPair();

    await saveVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId,
      privateKey: localKeyPair.privateKey,
    });
    await saveVerifiedVaultOpLogOfflineCache({
      userId,
      vaultId,
      currentHead: null,
      currentSequenceNumber: 0,
      operations: [],
      records: [],
      trustedDevices: [{
        vaultId,
        deviceId,
        publicSigningKey: otherKeyPair.publicKeyB64Url,
        deviceNameEncrypted: 'synthetic-test-device-name',
        addedByDeviceId: null,
        addedOpId: null,
        addedAt: new Date(0).toISOString(),
        trustEpoch: 0,
        status: 'trusted',
        revokedAt: null,
        revokedByDeviceId: null,
      }],
    });
    clearVaultOpLogDeviceIdentity();

    await expect(recoverVaultOpLogDeviceIdentityFromOfflineCache({
      userId,
      vaultId,
    })).resolves.toBeNull();
    expect(loadVaultOpLogDeviceIdentity()).toBeNull();
  });
});
