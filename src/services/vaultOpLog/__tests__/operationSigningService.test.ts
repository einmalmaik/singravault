// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  buildOperationSignedBody,
  generateDeviceSigningKeyPair,
  importDevicePublicKey,
  signOperation,
  verifyOperationSignature,
} from '../operationSigningService';
import { VaultSignatureError, type VaultOperationSignedBodyV1 } from '../types';

function baseBodyInput() {
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
    newRecordHash: 'hash-new',
    baseVaultHead: null,
    payloadCiphertextHash: 'hash-ct',
    payloadAadHash: 'hash-aad',
    createdAtClient: '2026-05-02T10:00:00.000Z',
    trustEpoch: 0,
  };
}

describe('buildOperationSignedBody', () => {
  it('pins the signature schema and echoes the fields', () => {
    const body = buildOperationSignedBody(baseBodyInput());
    expect(body.signatureSchema).toBe('device-signature-v1');
    expect(body.opId).toBe('op-1');
    expect(body.vaultId).toBe('vault-1');
  });

  it('rejects unknown op types', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        opType: 'not-an-op' as any,
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects unknown record types', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        recordType: 'not-a-record' as any,
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects non-ISO-8601 createdAtClient values', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        createdAtClient: '2026-05-02',
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects negative trustEpoch', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        trustEpoch: -1,
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects an empty intentId', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        intentId: '',
      }),
    ).toThrow(VaultSignatureError);
  });

  it('rejects a rebasedFromOpId equal to opId', () => {
    expect(() =>
      buildOperationSignedBody({
        ...baseBodyInput(),
        rebasedFromOpId: 'op-1',
      }),
    ).toThrow(VaultSignatureError);
  });

  it('accepts a rebasedFromOpId that differs from opId', () => {
    const body = buildOperationSignedBody({
      ...baseBodyInput(),
      opId: 'op-2',
      rebasedFromOpId: 'op-1',
    });
    expect(body.rebasedFromOpId).toBe('op-1');
    expect(body.opId).toBe('op-2');
    expect(body.intentId).toBe('intent-1');
  });

  it('echoes previousCiphertextHash verbatim', () => {
    const body = buildOperationSignedBody({
      ...baseBodyInput(),
      opType: 'update',
      baseRecordVersion: 1,
      previousCiphertextHash: 'ct-hash-1',
    });
    expect(body.previousCiphertextHash).toBe('ct-hash-1');
  });
});

describe('signOperation / verifyOperationSignature', () => {
  it('signs and verifies a valid operation', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);
    expect(signed.signature.length).toBeGreaterThan(0);
    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const ok = await verifyOperationSignature(signed, importedPublic);
    expect(ok).toBe(true);
  });

  it('rejects a signature that was produced by a different key', async () => {
    const keyA = await generateDeviceSigningKeyPair();
    const keyB = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyA.privateKey);
    const importedB = await importDevicePublicKey(keyB.publicKeyB64Url);
    const ok = await verifyOperationSignature(signed, importedB);
    expect(ok).toBe(false);
  });

  it('rejects an operation whose body was mutated after signing', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);
    const mutated = {
      ...signed,
      body: { ...signed.body, recordId: 'tampered' } as VaultOperationSignedBodyV1,
    };
    // `opHash` no longer matches the body, so verification throws.
    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    await expect(verifyOperationSignature(mutated, importedPublic)).rejects.toBeInstanceOf(
      VaultSignatureError,
    );
  });

  it('detects a mutation of the signed body even if the caller recomputes opHash', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);

    const { computeOpHash } = await import('../recordHashes');
    const mutatedBody: VaultOperationSignedBodyV1 = { ...signed.body, recordId: 'tampered' };
    const forgedOpHash = await computeOpHash(mutatedBody);
    const forged = { body: mutatedBody, signature: signed.signature, opHash: forgedOpHash };

    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const ok = await verifyOperationSignature(forged, importedPublic);
    expect(ok).toBe(false);
  });

  it('rejects a structurally invalid signature', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);
    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    // Truncate the signature by one byte's worth of base64url.
    const truncated = { ...signed, signature: signed.signature.slice(0, signed.signature.length - 2) };
    await expect(verifyOperationSignature(truncated, importedPublic)).rejects.toBeInstanceOf(
      VaultSignatureError,
    );
  });

  it('rejects a malformed base64url signature', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);
    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const malformed = { ...signed, signature: '!!!' };
    await expect(verifyOperationSignature(malformed, importedPublic)).rejects.toBeInstanceOf(
      VaultSignatureError,
    );
  });

  it('rejects an unknown signatureSchema', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const body = buildOperationSignedBody(baseBodyInput());
    const signed = await signOperation(body, keyPair.privateKey);
    const importedPublic = await importDevicePublicKey(keyPair.publicKeyB64Url);
    const cursed = {
      ...signed,
      body: { ...signed.body, signatureSchema: 'device-signature-v2' as unknown as typeof signed.body.signatureSchema },
    };
    await expect(verifyOperationSignature(cursed, importedPublic)).rejects.toBeInstanceOf(
      VaultSignatureError,
    );
  });
});

describe('importDevicePublicKey', () => {
  it('rejects a malformed base64url public key', async () => {
    await expect(importDevicePublicKey('!!!')).rejects.toBeInstanceOf(VaultSignatureError);
  });

  it('rejects a non-SPKI byte sequence', async () => {
    // 32 random bytes are not a valid SPKI-encoded ECDSA P-256 key.
    const bogus = crypto.getRandomValues(new Uint8Array(32));
    const { encodeBase64Url } = await import('../canonicalJson');
    await expect(importDevicePublicKey(encodeBase64Url(bogus))).rejects.toBeInstanceOf(
      VaultSignatureError,
    );
  });
});
