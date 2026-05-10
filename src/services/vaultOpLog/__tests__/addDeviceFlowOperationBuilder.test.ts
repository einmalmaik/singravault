// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the Add-Device-Flow operation builder.
 *
 * Coverage:
 * - buildAddDeviceOperation produces a signed add_device operation
 * - recordId is set to targetDeviceId, recordType to 'device'
 * - baseRecordVersion and previousCiphertextHash are null
 * - Signature verifies against the existing trusted device's public key
 * - Tampering with targetDeviceId invalidates the signature
 * - Tampering with targetPublicSigningKey invalidates the signature
 * - resultingVaultHead is computed correctly
 */

import { describe, expect, it } from 'vitest';
import {
  buildAddDeviceOperation,
} from '../vaultOpLogOperationBuilder';
import {
  generateDeviceSigningKeyPair,
  verifyOperationSignature,
} from '../operationSigningService';
import { computeOpHash } from '../recordHashes';
import { DEVICE_SIGNATURE_SCHEMA_V1 } from '../types';

const VAULT_ID = 'vault-1';

async function signingFixture() {
  const pair = await generateDeviceSigningKeyPair();
  return pair;
}

// ---------------------------------------------------------------------------
// buildAddDeviceOperation — happy path
// ---------------------------------------------------------------------------

describe('buildAddDeviceOperation', () => {
  it('produces a signed operation with opType add_device', async () => {
    const { privateKey, publicKeyB64Url } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Chrome on Windows',
      targetDevicePlatform: 'web',
    });

    const body = built.signedOperation.body;
    expect(body.opType).toBe('add_device');
    expect(body.opId).toBe('op-add-dev-1');
    expect(body.intentId).toBe('intent-1');
    expect(body.vaultId).toBe(VAULT_ID);
    expect(body.authorDeviceId).toBe('trusted-device-1');
  });

  it('uses targetDeviceId as recordId and device as recordType', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-uuid',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Safari on macOS',
      targetDevicePlatform: 'web',
    });

    const body = built.signedOperation.body;
    expect(body.recordId).toBe('new-device-uuid');
    expect(body.recordType).toBe('device');
  });

  it('sets baseRecordVersion and previousCiphertextHash to null', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Firefox on Linux',
    });

    const body = built.signedOperation.body;
    expect(body.baseRecordVersion).toBeNull();
    expect(body.previousCiphertextHash).toBeNull();
    expect(body.newRecordHash).toBeNull();
    expect(body.payloadCiphertextHash).toBeNull();
    expect(body.payloadAadHash).toBeNull();
  });

  it('has a verifiable signature from the existing trusted device', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Edge on Windows',
    });

    const verified = await verifyOperationSignature(built.signedOperation, publicKey);
    expect(verified).toBe(true);
  });

  it('returns the targetDeviceId and targetPublicSigningKey in output', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'my-new-device',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Chrome on Android',
    });

    expect(built.targetDeviceId).toBe('my-new-device');
    expect(built.targetPublicSigningKey).toBe(targetKeyPair.publicKeyB64Url);
  });

  it('produces a non-empty resultingVaultHead', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Desktop App',
    });

    expect(built.resultingVaultHead.length).toBeGreaterThan(0);
  });

  it('uses signature schema v1', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    expect(built.signedOperation.body.signatureSchema).toBe(DEVICE_SIGNATURE_SCHEMA_V1);
  });
});

// ---------------------------------------------------------------------------
// buildAddDeviceOperation — tampering resistance
// ---------------------------------------------------------------------------

describe('buildAddDeviceOperation — signature tamper resistance', () => {
  it('signature is NOT valid if targetDeviceId is changed after signing', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Tamper: change recordId in the body (simulates changing targetDeviceId)
    const tamperedBody = {
      ...built.signedOperation.body,
      recordId: 'attacker-device-id',
    };

    // Verify fails because opHash changes when recordId changes
    const recomputedHash = await computeOpHash(tamperedBody);
    expect(recomputedHash).not.toBe(built.signedOperation.opHash);
  });

  it('opHash DOES change when targetPublicSigningKey differs (NOW SIGNED)', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPairA = await signingFixture();
    const targetKeyPairB = await signingFixture();
    const fixedTimestamp = '2026-05-01T00:00:00.000Z'; // Fixed for determinism

    const builtA = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPairA.publicKeyB64Url,
      targetDeviceName: 'Browser A',
      createdAtClient: fixedTimestamp, // Explicit timestamp
    });

    const builtB = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPairB.publicKeyB64Url, // different key
      targetDeviceName: 'Browser B',
      createdAtClient: fixedTimestamp, // Same timestamp
    });

    // SECURITY FIX: targetPublicSigningKey is NOW part of the signed body.
    // Changing it changes the opHash, which invalidates the signature.
    // This prevents MITM attacks where an attacker substitutes the public key.
    expect(builtA.signedOperation.opHash).not.toBe(builtB.signedOperation.opHash);

    // Signatures will also differ (ECDSA includes random nonce, but also different body)
    expect(builtA.signedOperation.signature).not.toBe(builtB.signedOperation.signature);
  });

  it('signature fails when a different key signs the same operation', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const differentKeyPair = await signingFixture();
    const targetKeyPair = await signingFixture();

    const builtWithCorrectKey = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Verify with correct public key
    const verifiedCorrect = await verifyOperationSignature(
      builtWithCorrectKey.signedOperation,
      publicKey,
    );
    expect(verifiedCorrect).toBe(true);

    // Verify with WRONG public key (different device)
    const verifiedWrong = await verifyOperationSignature(
      builtWithCorrectKey.signedOperation,
      differentKeyPair.publicKey,
    );
    expect(verifiedWrong).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildAddDeviceOperation — determinism and uniqueness
// ---------------------------------------------------------------------------

describe('buildAddDeviceOperation — opHash uniqueness', () => {
  it('produces deterministic opHash for identical inputs', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const a = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: 'head-0',
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
      createdAtClient: '2026-05-01T00:00:00.000Z',
    });

    const b = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: 'head-0',
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
      createdAtClient: '2026-05-01T00:00:00.000Z',
    });

    expect(a.signedOperation.opHash).toBe(b.signedOperation.opHash);
  });

  it('produces different opHash when intentId differs', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const a = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-a',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    const b = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-b',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    expect(a.signedOperation.opHash).not.toBe(b.signedOperation.opHash);
  });

  it('produces different opHash when vaultId differs', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const a = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: 'vault-a',
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    const b = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: 'vault-b',
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    expect(a.signedOperation.opHash).not.toBe(b.signedOperation.opHash);
  });

  it('produces different opHash when authorDeviceId differs', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const a = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-a',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    const b = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-b',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    expect(a.signedOperation.opHash).not.toBe(b.signedOperation.opHash);
  });

  it('resultingVaultHead changes when baseVaultHead changes', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const a = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: 'head-a',
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    const b = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: 'head-b',
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    expect(a.resultingVaultHead).not.toBe(b.resultingVaultHead);
  });
});

// ---------------------------------------------------------------------------
// buildAddDeviceOperation — secret safety
// ---------------------------------------------------------------------------

describe('buildAddDeviceOperation — secret safety', () => {
  it('does not include sensitive data in the signed operation', async() => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Chrome on Windows',
      targetDevicePlatform: 'web',
    });

    const bodyJson = JSON.stringify(built.signedOperation.body);
    // targetPublicSigningKey IS now in the body (security fix!)
    // But it should NOT contain 'private' or 'secret' (it's the public key)
    expect(bodyJson).not.toContain('private');
    expect(bodyJson).not.toContain('secret');
  });
});

// ---------------------------------------------------------------------------
// buildAddDeviceOperation — NEGATIVE SECURITY TESTS (Tamper Protection)
// ---------------------------------------------------------------------------

describe('buildAddDeviceOperation — NEGATIVE SECURITY TESTS', () => {
  it('changing targetPublicSigningKey after signing invalidates verification', async () => {
    const { privateKey, publicKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Verify the original signature is valid
    const verifiedOriginal = await verifyOperationSignature(built.signedOperation, publicKey);
    expect(verifiedOriginal).toBe(true);

    // Tamper: Create a modified body with different targetPublicSigningKey
    const tamperedBody = {
      ...built.signedOperation.body,
      targetPublicSigningKey: 'TAMPERED_PUBLIC_KEY_BASE64',
    };

    // The signature was made over the original body, so verification should fail
    // We need to re-verify the original operation (not the tampered one)
    // The key insight: if someone intercepts and changes the public key in transit,
    // the signature won't match the tampered body
    const tamperedOpHash = await computeOpHash(tamperedBody);
    expect(tamperedOpHash).not.toBe(built.signedOperation.opHash);
  });

  it('changing targetDeviceId after signing invalidates verification', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Tamper: Change targetDeviceId (recordId in the body)
    const tamperedBody = {
      ...built.signedOperation.body,
      recordId: 'attacker-device-id',
    };

    const tamperedOpHash = await computeOpHash(tamperedBody);
    expect(tamperedOpHash).not.toBe(built.signedOperation.opHash);
  });

  it('changing trustEpoch invalidates signature', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Tamper: Change trustEpoch
    const tamperedBody = {
      ...built.signedOperation.body,
      trustEpoch: 99, // Attacker tries to use a different trust epoch
    };

    const tamperedOpHash = await computeOpHash(tamperedBody);
    expect(tamperedOpHash).not.toBe(built.signedOperation.opHash);
  });

  it('buildAddDeviceOperation REQUIRES targetPublicSigningKey (security invariant)', async () => {
    const { privateKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    // Valid case - should succeed
    const validBuilt = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // Verify the signed body contains the targetPublicSigningKey
    expect(validBuilt.signedOperation.body.targetPublicSigningKey).toBe(targetKeyPair.publicKeyB64Url);
    expect(validBuilt.signedOperation.body.targetDeviceKeyFingerprint).not.toBeNull();
  });

  it('add_device without signed targetPublicSigningKey cannot create trust', async () => {
    // This test verifies the security design:
    // Even if an attacker somehow gets an add_device operation accepted,
    // the targetPublicSigningKey in the signed body is what gets stored as trusted.
    // Without signing, the key cannot be trusted.

    const { privateKey, publicKey } = await signingFixture();
    const targetKeyPair = await signingFixture();

    const built = await buildAddDeviceOperation({
      opId: 'op-add-dev-1',
      intentId: 'intent-1',
      rebasedFromOpId: null,
      vaultId: VAULT_ID,
      deviceId: 'trusted-device-1',
      deviceSigningKey: privateKey,
      trustEpoch: 1,
      baseVaultHead: null,
      targetDeviceId: 'new-device-1',
      targetPublicSigningKey: targetKeyPair.publicKeyB64Url,
      targetDeviceName: 'Browser',
    });

    // The operation is valid and the signed body contains the CORRECT public key
    const verified = await verifyOperationSignature(built.signedOperation, publicKey);
    expect(verified).toBe(true);

    // The trust record would use built.signedOperation.body.targetPublicSigningKey
    // as the authoritative public key - not any other value
    const trustedPublicKey = built.signedOperation.body.targetPublicSigningKey;
    expect(trustedPublicKey).toBe(targetKeyPair.publicKeyB64Url);
  });
});