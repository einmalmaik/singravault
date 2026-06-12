// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `cryptoRecordService` — record key derivation and AEAD seal / open
 * with AAD-bound context verification.
 *
 * This module is the single place in the operation-log layer that
 * touches record plaintext. All callers must pass the full
 * `RecordAadV1` context on both seal and open paths. The open path
 * refuses to decrypt if the AAD byte representation, the AAD hash or
 * the ciphertext hash do not match the record-as-received.
 *
 * Key derivation uses HKDF-SHA-256 over a caller-supplied vault
 * encryption key. The KDF context is canonicalised so two clients
 * always derive the same record key for the same (vaultId, recordId,
 * recordType, keyVersion) tuple.
 *
 * Powered by DIS — Defensive Integration Shield: the HKDF and
 * AES-256-GCM primitives come from `@dis/shield`. This module owns
 * only the canonical KDF context, the AAD contract and the hash
 * verification order.
 */

import { deriveHkdfSha256Bits } from '@dis/shield/kdf';
import { aesGcmDecrypt, aesGcmEncrypt, importAesGcmRawKey } from '@dis/shield/aead';
import { randomBytes } from '@dis/shield/random';
import {
  canonicalizeVaultStructure,
  constantTimeEquals,
  decodeBase64Url,
  encodeBase64Url,
  isUint8ArrayLike,
} from './canonicalJson';
import {
  buildRecordAad,
  encodeRecordAadBytes,
} from './recordAad';
import {
  computeAadHash,
  computeCiphertextHash,
} from './recordHashes';
import {
  RECORD_ENCRYPTION_SCHEMA_V1,
  VaultCryptoError,
  isRecordType,
  type BuildRecordAadInput,
  type OpenedRecordV1,
  type RecordAadV1,
  type SealedRecordV1,
} from './types';

const RECORD_KEY_INFO_PURPOSE = 'singra-vault/record-key-v1' as const;
const AEAD_NONCE_BYTE_LENGTH = 12;

// ---------------------------------------------------------------
// Record key derivation (HKDF-SHA-256)
// ---------------------------------------------------------------

/**
 * Inputs to record key derivation. `vaultEncryptionKey` is the raw
 * bytes of the vault-level symmetric key already unlocked by the
 * caller (see `cryptoService.ts`). Callers are responsible for
 * wiping it after use.
 */
export interface DeriveRecordKeyInput {
  readonly vaultEncryptionKey: Uint8Array;
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: string;
  readonly keyVersion: number;
}

/**
 * Deterministically derive a 32-byte record key from the vault
 * encryption key. Same inputs always produce the same output. A
 * one-byte change in any input produces a different output with
 * overwhelming probability.
 */
export async function deriveRecordKey(input: DeriveRecordKeyInput): Promise<Uint8Array> {
  if (!isRecordType(input.recordType)) {
    throw new VaultCryptoError('record_type_invalid', `unknown record type: ${input.recordType}`);
  }
  if (!isUint8ArrayLike(input.vaultEncryptionKey) || input.vaultEncryptionKey.length < 16) {
    throw new VaultCryptoError('key_material_invalid', 'vault encryption key must be at least 16 bytes');
  }
  const info = canonicalizeVaultStructure({
    purpose: RECORD_KEY_INFO_PURPOSE,
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    keyVersion: input.keyVersion,
  });
  return deriveHkdfSha256Bits(input.vaultEncryptionKey, { info });
}

// ---------------------------------------------------------------
// AEAD seal / open
// ---------------------------------------------------------------

export interface SealRecordInput {
  readonly plaintext: Uint8Array;
  readonly recordKey: Uint8Array;
  readonly aadInput: BuildRecordAadInput;
  readonly nonce?: Uint8Array;
}

/**
 * Seal a plaintext record. Produces a `SealedRecordV1` ready to be
 * sent to the server alongside a `create` / `update` / `restore` /
 * `move` operation.
 *
 * The caller supplies the AAD inputs (vaultId, recordId, recordType,
 * recordVersion, keyVersion). The encryption schema is pinned.
 */
export async function sealRecord(input: SealRecordInput): Promise<SealedRecordV1> {
  if (!isUint8ArrayLike(input.plaintext)) {
    throw new VaultCryptoError('key_material_invalid', 'plaintext must be a Uint8Array');
  }
  const aad = buildRecordAad(input.aadInput);
  const aadBytes = encodeRecordAadBytes(aad);
  const nonce = input.nonce ?? randomBytes(AEAD_NONCE_BYTE_LENGTH);
  if (nonce.length !== AEAD_NONCE_BYTE_LENGTH) {
    throw new VaultCryptoError('key_material_invalid', 'nonce must be 12 bytes');
  }
  const key = await importAeadKey(input.recordKey, ['encrypt']);
  const ciphertext = await aesGcmEncrypt(key, nonce, input.plaintext, aadBytes);
  const nonceB64Url = encodeBase64Url(nonce);
  const ciphertextB64Url = encodeBase64Url(ciphertext);
  const aadHash = await computeAadHash(aad);
  const ciphertextHash = await computeCiphertextHash({
    aadHash,
    nonceB64Url,
    ciphertextB64Url,
    vaultId: aad.vaultId,
    recordId: aad.recordId,
    recordType: aad.recordType,
    recordVersion: aad.recordVersion,
    keyVersion: aad.keyVersion,
  });
  return {
    aad,
    aadHash,
    nonceB64Url,
    ciphertextB64Url,
    ciphertextHash,
  };
}

export interface OpenRecordInput {
  readonly sealed: SealedRecordV1;
  readonly recordKey: Uint8Array;
  readonly expectedAadInput: BuildRecordAadInput;
  readonly expectedAadHash?: string;
  readonly expectedCiphertextHash?: string;
}

/**
 * Open a sealed record, but only after verifying the AAD context and
 * the advertised hashes. Any mismatch is thrown as a typed
 * `VaultCryptoError` and the AEAD open is not even attempted when
 * the metadata does not match — that makes sure the AEAD failure
 * counter cannot be used as an oracle.
 *
 * The state machine must call this with the context it expects for
 * the record based on its own verified operation log, never with
 * context reconstructed from the server-returned row.
 */
export async function openRecord(input: OpenRecordInput): Promise<OpenedRecordV1> {
  const expectedAad = buildRecordAad(input.expectedAadInput);
  const actualAadBytes = encodeRecordAadBytes(input.sealed.aad);
  const expectedAadBytes = encodeRecordAadBytes(expectedAad);
  if (!constantTimeEquals(actualAadBytes, expectedAadBytes)) {
    throw new VaultCryptoError('unexpected_record_context', 'AAD does not match expected record context');
  }
  if (input.expectedAadHash !== undefined && input.expectedAadHash !== input.sealed.aadHash) {
    throw new VaultCryptoError('aad_hash_mismatch', 'AAD hash mismatch');
  }
  const recomputedAadHash = await computeAadHash(input.sealed.aad);
  if (recomputedAadHash !== input.sealed.aadHash) {
    throw new VaultCryptoError('aad_hash_mismatch', 'AAD hash does not match canonical AAD bytes');
  }
  const recomputedCiphertextHash = await computeCiphertextHash({
    aadHash: input.sealed.aadHash,
    nonceB64Url: input.sealed.nonceB64Url,
    ciphertextB64Url: input.sealed.ciphertextB64Url,
    vaultId: input.sealed.aad.vaultId,
    recordId: input.sealed.aad.recordId,
    recordType: input.sealed.aad.recordType,
    recordVersion: input.sealed.aad.recordVersion,
    keyVersion: input.sealed.aad.keyVersion,
  });
  if (recomputedCiphertextHash !== input.sealed.ciphertextHash) {
    throw new VaultCryptoError('ciphertext_hash_mismatch', 'ciphertext hash does not match ciphertext bytes');
  }
  if (
    input.expectedCiphertextHash !== undefined
    && input.expectedCiphertextHash !== input.sealed.ciphertextHash
  ) {
    throw new VaultCryptoError('ciphertext_hash_mismatch', 'ciphertext hash mismatch against expectation');
  }
  if (input.sealed.aad.encryptionSchema !== RECORD_ENCRYPTION_SCHEMA_V1) {
    throw new VaultCryptoError('schema_version_unsupported', 'unknown encryption schema');
  }

  const nonce = decodeBase64Url(input.sealed.nonceB64Url);
  const ciphertext = decodeBase64Url(input.sealed.ciphertextB64Url);
  const key = await importAeadKey(input.recordKey, ['decrypt']);

  try {
    const plaintext = await aesGcmDecrypt(key, nonce, ciphertext, expectedAadBytes);
    return { plaintext, aad: expectedAad };
  } catch {
    throw new VaultCryptoError('aead_decryption_failed', 'AEAD decryption failed');
  }
}

/**
 * Re-export of `buildRecordAad` so consumers can import a single
 * module for all record-crypto concerns.
 */
export { buildRecordAad, encodeRecordAadBytes } from './recordAad';
export type { RecordAadV1, SealedRecordV1, OpenedRecordV1 } from './types';

// ---------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------

async function importAeadKey(rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (!isUint8ArrayLike(rawKey) || rawKey.length !== 32) {
    throw new VaultCryptoError('key_material_invalid', 'record key must be 32 bytes');
  }
  return importAesGcmRawKey(rawKey, usages);
}
