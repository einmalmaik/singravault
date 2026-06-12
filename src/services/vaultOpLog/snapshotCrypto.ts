// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Snapshot-specific crypto: key derivation and AEAD seal / open.
 *
 * Powered by DIS — Defensive Integration Shield: HKDF-SHA-256,
 * AES-256-GCM and SHA-256 come from `@dis/shield`. No custom cipher
 * modes. The snapshot key is derived from the vault encryption key
 * via HKDF-SHA-256 with a snapshot-specific purpose.
 */

import { deriveHkdfSha256Bits } from '@dis/shield/kdf';
import { aesGcmDecrypt, aesGcmEncrypt, importAesGcmRawKey } from '@dis/shield/aead';
import { sha256Bytes } from '@dis/shield/integrity';
import { randomBytes } from '@dis/shield/random';
import {
  canonicalizeVaultStructure,
  decodeBase64Url,
  encodeBase64Url,
  isUint8ArrayLike,
} from './canonicalJson';
import { computeAadHash } from './recordHashes';
import {
  VaultCryptoError,
  type RecordAadV1,
} from './types';
import {
  SNAPSHOT_KEY_DERIVATION_PURPOSE,
  SNAPSHOT_AAD_SCHEMA_V1,
  type SnapshotAadV1,
} from './trustedSnapshotTypes';

const AEAD_NONCE_BYTE_LENGTH = 12;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export interface DeriveSnapshotKeyInput {
  readonly vaultEncryptionKey: Uint8Array;
  readonly vaultId: string;
  readonly snapshotId: string;
  readonly deviceId: string;
  readonly trustEpoch: number;
}

/**
 * Derive a 32-byte snapshot encryption key from the vault key.
 * Deterministic for the same inputs; one-byte change → different key.
 */
export async function deriveSnapshotKey(input: DeriveSnapshotKeyInput): Promise<Uint8Array> {
  if (!isUint8ArrayLike(input.vaultEncryptionKey) || input.vaultEncryptionKey.length < 16) {
    throw new VaultCryptoError('key_material_invalid', 'vault encryption key must be at least 16 bytes');
  }
  const info = canonicalizeVaultStructure({
    purpose: SNAPSHOT_KEY_DERIVATION_PURPOSE,
    vaultId: input.vaultId,
    snapshotId: input.snapshotId,
    deviceId: input.deviceId,
    trustEpoch: input.trustEpoch,
  });
  return deriveHkdfSha256Bits(input.vaultEncryptionKey, { info });
}

// ---------------------------------------------------------------------------
// AEAD seal / open for snapshot plaintext
// ---------------------------------------------------------------------------

export interface SealSnapshotInput {
  readonly plaintext: Uint8Array;
  readonly snapshotKey: Uint8Array;
  readonly aad: SnapshotAadV1;
  readonly nonce?: Uint8Array;
}

export interface SealedSnapshotV1 {
  readonly aad: SnapshotAadV1;
  readonly aadHash: string;
  readonly nonceB64Url: string;
  readonly ciphertextB64Url: string;
}

/**
 * Encrypt a snapshot plaintext with AES-GCM and snapshot AAD.
 */
export async function sealSnapshot(input: SealSnapshotInput): Promise<SealedSnapshotV1> {
  if (!isUint8ArrayLike(input.plaintext)) {
    throw new VaultCryptoError('key_material_invalid', 'snapshot plaintext must be a Uint8Array');
  }
  const aadHash = await computeSnapshotAadHash(input.aad);
  const aadBytes = canonicalizeVaultStructure(input.aad);
  const nonce = input.nonce ?? randomBytes(AEAD_NONCE_BYTE_LENGTH);
  if (nonce.length !== AEAD_NONCE_BYTE_LENGTH) {
    throw new VaultCryptoError('key_material_invalid', 'nonce must be 12 bytes');
  }
  const key = await importSnapshotAeadKey(input.snapshotKey, ['encrypt']);
  const ciphertext = await aesGcmEncrypt(key, nonce, input.plaintext, aadBytes);
  return {
    aad: input.aad,
    aadHash,
    nonceB64Url: encodeBase64Url(nonce),
    ciphertextB64Url: encodeBase64Url(ciphertext),
  };
}

export interface OpenSnapshotInput {
  readonly sealed: SealedSnapshotV1;
  readonly snapshotKey: Uint8Array;
  readonly expectedAad: SnapshotAadV1;
  readonly expectedAadHash?: string;
}

/**
 * Decrypt a snapshot ciphertext after AAD verification.
 * Throws `VaultCryptoError` on any mismatch.
 */
export async function openSnapshot(input: OpenSnapshotInput): Promise<Uint8Array> {
  const expectedAadBytes = canonicalizeVaultStructure(input.expectedAad);
  const actualAadBytes = canonicalizeVaultStructure(input.sealed.aad);
  if (!constantTimeEquals(expectedAadBytes, actualAadBytes)) {
    throw new VaultCryptoError('unexpected_record_context', 'snapshot AAD does not match expected context');
  }
  if (input.expectedAadHash !== undefined && input.expectedAadHash !== input.sealed.aadHash) {
    throw new VaultCryptoError('aad_hash_mismatch', 'snapshot AAD hash mismatch');
  }
  const recomputedAadHash = await computeSnapshotAadHash(input.sealed.aad);
  if (recomputedAadHash !== input.sealed.aadHash) {
    throw new VaultCryptoError('aad_hash_mismatch', 'snapshot AAD hash does not match canonical bytes');
  }

  const nonce = decodeBase64Url(input.sealed.nonceB64Url);
  const ciphertext = decodeBase64Url(input.sealed.ciphertextB64Url);
  const key = await importSnapshotAeadKey(input.snapshotKey, ['decrypt']);

  try {
    return await aesGcmDecrypt(key, nonce, ciphertext, expectedAadBytes);
  } catch {
    throw new VaultCryptoError('aead_decryption_failed', 'snapshot AEAD decryption failed');
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function importSnapshotAeadKey(rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (!isUint8ArrayLike(rawKey) || rawKey.length !== 32) {
    throw new VaultCryptoError('key_material_invalid', 'snapshot key must be 32 bytes');
  }
  return importAesGcmRawKey(rawKey, usages);
}

/**
 * SHA-256 of canonical snapshot AAD bytes, base64url.
 */
export async function computeSnapshotAadHash(aad: SnapshotAadV1): Promise<string> {
  const bytes = canonicalizeVaultStructure(aad);
  return encodeBase64Url(await sha256Bytes(bytes));
}

/**
 * Compute the deterministic snapshot hash over all signed envelope
 * fields (everything except the signature itself).
 */
export async function computeSnapshotHash(envelope: {
  readonly schema: string;
  readonly snapshotId: string;
  readonly vaultId: string;
  readonly createdAt: string;
  readonly createdByDeviceId: string;
  readonly verifiedVaultHead: string | null;
  readonly trustEpoch: number;
  readonly encryptionSchema: string;
  readonly signatureSchema: string;
  readonly nonce: string;
  readonly aadHash: string;
  readonly snapshotCiphertext: string;
}): Promise<string> {
  const payload = {
    schema: 'snapshot-hash-v1',
    snapshotId: envelope.snapshotId,
    vaultId: envelope.vaultId,
    createdAt: envelope.createdAt,
    createdByDeviceId: envelope.createdByDeviceId,
    verifiedVaultHead: envelope.verifiedVaultHead,
    trustEpoch: envelope.trustEpoch,
    encryptionSchema: envelope.encryptionSchema,
    signatureSchema: envelope.signatureSchema,
    nonce: envelope.nonce,
    aadHash: envelope.aadHash,
    snapshotCiphertext: envelope.snapshotCiphertext,
  };
  const bytes = canonicalizeVaultStructure(payload);
  return encodeBase64Url(await sha256Bytes(bytes));
}

function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
