// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import { generateDeviceSigningKeyPair } from '../operationSigningService';
import { recoverVaultOpLogDeviceIdentity } from '../vaultOpLogDeviceIdentityRecovery';
import { loadVerifiedVaultOpLogDeviceContext } from '../vaultOpLogDeviceIdentityRecovery';
import { saveVaultOpLogDeviceSigningKey } from '../vaultOpLogDeviceSigningKeyStore';
import {
  clearVaultOpLogDeviceIdentity,
  loadVaultOpLogDeviceIdentity,
} from '../vaultOpLogDeviceStore';

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
});
