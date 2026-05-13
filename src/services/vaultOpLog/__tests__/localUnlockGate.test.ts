// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import {
  evaluateOfflineVaultGates,
  validateOfflineIdentity,
  type LocalDeviceSigningTrustGate,
  type LocalTrustWorkingSetGate,
  type OfflineIdentityContext,
  type VaultKeyUnlockGate,
} from '../localUnlockGate';
import {
  VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
  VAULT_PROTECTION_MODE_MASTER_ONLY,
} from '@/services/deviceKeyProtectionPolicy';

const identity: OfflineIdentityContext = {
  userId: 'user-offline-gate',
  email: 'test-user@example.invalid',
  updatedAt: '2026-05-13T00:00:00.000Z',
  vaultId: 'vault-offline-gate',
};

const unlocked: VaultKeyUnlockGate = {
  vaultKeyAvailable: true,
  protectionMode: VAULT_PROTECTION_MODE_MASTER_ONLY,
  deviceKeyAvailable: false,
  deviceKeyVerified: false,
};

const verifiedWorkingSet: LocalTrustWorkingSetGate = {
  exists: true,
  structureValid: true,
  manifestVerified: true,
  opLogComplete: true,
  lastVerifiedVaultHead: 'head-1',
  lastVerifiedSequence: 1,
  trustEpoch: 1,
};

const trustedSigningKey: LocalDeviceSigningTrustGate = {
  privateSigningKeyAvailable: true,
  publicKeyMatchesTrustedDevice: true,
  deviceTrustedAtHead: true,
  deviceRevokedAtHead: false,
};

describe('localUnlockGate', () => {
  it('blocks offline mode without a token-free offline identity', () => {
    const result = evaluateOfflineVaultGates({
      identity: null,
      unlock: unlocked,
      workingSet: verifiedWorkingSet,
      signingTrust: trustedSigningKey,
    });

    expect(result.mode).toBe('offlineLocked');
    expect(result.reason).toBe('offline_identity_missing');
  });

  it('rejects offline identities that contain auth tokens', () => {
    const result = validateOfflineIdentity({
      ...identity,
      access_token: 'synthetic-token-not-real',
    });

    expect(result).toEqual({ kind: 'invalid', reason: 'offline_identity_contains_auth_token' });
  });

  it('blocks Device-Key-required unlock when the Device Key is missing', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: {
        vaultKeyAvailable: false,
        protectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
        deviceKeyAvailable: false,
        deviceKeyVerified: false,
      },
      workingSet: verifiedWorkingSet,
      signingTrust: trustedSigningKey,
    });

    expect(result.mode).toBe('offlineLocked');
    expect(result.reason).toBe('vault_key_missing');
    expect(result.canReadVerifiedRecords).toBe(false);
  });

  it('blocks master-password-only fallback when device_key_required is active', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: {
        vaultKeyAvailable: true,
        protectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
        deviceKeyAvailable: false,
        deviceKeyVerified: false,
      },
      workingSet: verifiedWorkingSet,
      signingTrust: trustedSigningKey,
    });

    expect(result.mode).toBe('offlineLocked');
    expect(result.reason).toBe('device_key_missing');
    expect(result.canWriteSignedPendingOperations).toBe(false);
  });

  it('blocks offline use without a verified working set', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: unlocked,
      workingSet: null,
      signingTrust: trustedSigningKey,
    });

    expect(result.mode).toBe('offlineLocked');
    expect(result.reason).toBe('verified_working_set_missing');
  });

  it('allows read-only but not writes when the signing key is missing and policy permits read-only', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: unlocked,
      workingSet: verifiedWorkingSet,
      signingTrust: {
        ...trustedSigningKey,
        privateSigningKeyAvailable: false,
      },
      allowReadOnlyWithoutSigningKey: true,
    });

    expect(result.mode).toBe('offlineReadOnly');
    expect(result.canReadVerifiedRecords).toBe(true);
    expect(result.canWriteSignedPendingOperations).toBe(false);
    expect(result.reason).toBe('local_signing_key_missing');
  });

  it('blocks offline writes when the local signing public key does not match trust state', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: unlocked,
      workingSet: verifiedWorkingSet,
      signingTrust: {
        ...trustedSigningKey,
        publicKeyMatchesTrustedDevice: false,
      },
    });

    expect(result.mode).toBe('offlineLocked');
    expect(result.reason).toBe('local_signing_key_mismatch');
  });

  it('allows offlineReady only when identity, unlock and local trust gates all pass', () => {
    const result = evaluateOfflineVaultGates({
      identity,
      unlock: {
        vaultKeyAvailable: true,
        protectionMode: VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED,
        deviceKeyAvailable: true,
        deviceKeyVerified: true,
      },
      workingSet: verifiedWorkingSet,
      signingTrust: trustedSigningKey,
    });

    expect(result.mode).toBe('offlineReady');
    expect(result.canReadVerifiedRecords).toBe(true);
    expect(result.canWriteSignedPendingOperations).toBe(true);
    expect(result.reason).toBeNull();
  });
});
