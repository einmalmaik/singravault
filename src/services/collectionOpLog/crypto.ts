// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import {
  canonicalizeVaultStructure,
  decodeBase64Url,
  encodeBase64Url,
} from '@/services/vaultOpLog/canonicalJson';
import { sha256Base64Url } from '@/services/vaultOpLog/recordHashes';
import {
  COLLECTION_AAD_SCHEMA_V1,
  COLLECTION_ENCRYPTION_SCHEMA_V1,
  type CollectionRecordAadV1,
  type CollectionRecordType,
  type SealedCollectionRecordV1,
} from './types';

const NONCE_BYTES = 12;

export function buildCollectionRecordAad(input: {
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
}): CollectionRecordAadV1 {
  return {
    app: 'singra-vault',
    aadSchema: COLLECTION_AAD_SCHEMA_V1,
    collectionId: input.collectionId,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: input.recordVersion,
    keyVersion: input.keyVersion,
    encryptionSchema: COLLECTION_ENCRYPTION_SCHEMA_V1,
  };
}

export function encodeCollectionRecordAadBytes(aad: CollectionRecordAadV1): Uint8Array {
  return canonicalizeVaultStructure(aad);
}

export async function deriveCollectionRecordKey(input: {
  readonly collectionKey: Uint8Array;
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly keyVersion: number;
}): Promise<Uint8Array> {
  if (input.collectionKey.length < 16) {
    throw new Error('collection key must be at least 16 bytes');
  }

  const baseKey = await crypto.subtle.importKey(
    'raw',
    input.collectionKey as unknown as ArrayBuffer,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );
  const info = canonicalizeVaultStructure({
    purpose: 'singra-vault/collection-record-key-v1',
    collectionId: input.collectionId,
    recordId: input.recordId,
    recordType: input.recordType,
    keyVersion: input.keyVersion,
  });
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as unknown as ArrayBuffer,
      info: info as unknown as ArrayBuffer,
    },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

export async function computeCollectionAadHash(aad: CollectionRecordAadV1): Promise<string> {
  return sha256Base64Url(encodeCollectionRecordAadBytes(aad));
}

export async function computeCollectionCiphertextHash(input: {
  readonly aadHash: string;
  readonly nonceB64Url: string;
  readonly ciphertextB64Url: string;
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: string;
  readonly recordVersion: number;
  readonly keyVersion: number;
}): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    schema: 'collection-ciphertext-hash-v1',
    aadHash: input.aadHash,
    ciphertext: input.ciphertextB64Url,
    collectionId: input.collectionId,
    encryptionSchema: COLLECTION_ENCRYPTION_SCHEMA_V1,
    keyVersion: input.keyVersion,
    nonce: input.nonceB64Url,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: input.recordVersion,
  }));
}

export async function sealCollectionRecord(input: {
  readonly plaintext: Uint8Array;
  readonly collectionKey: Uint8Array;
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly nonce?: Uint8Array;
}): Promise<SealedCollectionRecordV1> {
  const aad = buildCollectionRecordAad(input);
  const aadBytes = encodeCollectionRecordAadBytes(aad);
  const recordKey = await deriveCollectionRecordKey(input);
  let ciphertextBuffer: ArrayBuffer;
  const nonce = input.nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
  try {
    const key = await importAesKey(recordKey, ['encrypt']);
    if (nonce.length !== NONCE_BYTES) {
      throw new Error('collection record nonce must be 12 bytes');
    }
    ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as unknown as ArrayBuffer, additionalData: aadBytes as unknown as ArrayBuffer, tagLength: 128 },
      key,
      input.plaintext as unknown as ArrayBuffer,
    );
  } finally {
    recordKey.fill(0);
  }
  const nonceB64Url = encodeBase64Url(nonce);
  const ciphertextB64Url = encodeBase64Url(new Uint8Array(ciphertextBuffer));
  const aadHash = await computeCollectionAadHash(aad);
  const ciphertextHash = await computeCollectionCiphertextHash({
    aadHash,
    nonceB64Url,
    ciphertextB64Url,
    collectionId: aad.collectionId,
    recordId: aad.recordId,
    recordType: aad.recordType,
    recordVersion: aad.recordVersion,
    keyVersion: aad.keyVersion,
  });
  return { aad, aadHash, nonceB64Url, ciphertextB64Url, ciphertextHash };
}

export async function openVerifiedCollectionRecord(input: {
  readonly sealed: SealedCollectionRecordV1;
  readonly collectionKey: Uint8Array;
  readonly expected: {
    readonly collectionId: string;
    readonly recordId: string;
    readonly recordType: CollectionRecordType;
    readonly recordVersion: number;
    readonly keyVersion: number;
  };
  readonly expectedAadHash: string;
  readonly expectedCiphertextHash: string;
}): Promise<Uint8Array> {
  const expectedAad = buildCollectionRecordAad(input.expected);
  const aadHash = await computeCollectionAadHash(input.sealed.aad);
  if (
    aadHash !== input.expectedAadHash
    || input.sealed.aadHash !== input.expectedAadHash
    || !bytesEqual(encodeCollectionRecordAadBytes(input.sealed.aad), encodeCollectionRecordAadBytes(expectedAad))
  ) {
    throw new Error('collection record AAD mismatch');
  }
  const ciphertextHash = await computeCollectionCiphertextHash({
    aadHash: input.sealed.aadHash,
    nonceB64Url: input.sealed.nonceB64Url,
    ciphertextB64Url: input.sealed.ciphertextB64Url,
    collectionId: input.sealed.aad.collectionId,
    recordId: input.sealed.aad.recordId,
    recordType: input.sealed.aad.recordType,
    recordVersion: input.sealed.aad.recordVersion,
    keyVersion: input.sealed.aad.keyVersion,
  });
  if (ciphertextHash !== input.expectedCiphertextHash || input.sealed.ciphertextHash !== input.expectedCiphertextHash) {
    throw new Error('collection record ciphertext hash mismatch');
  }

  const recordKey = await deriveCollectionRecordKey({
    collectionKey: input.collectionKey,
    collectionId: input.expected.collectionId,
    recordId: input.expected.recordId,
    recordType: input.expected.recordType,
    keyVersion: input.expected.keyVersion,
  });
  try {
    const key = await importAesKey(recordKey, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: decodeBase64Url(input.sealed.nonceB64Url) as unknown as ArrayBuffer,
        additionalData: encodeCollectionRecordAadBytes(expectedAad) as unknown as ArrayBuffer,
        tagLength: 128,
      },
      key,
      decodeBase64Url(input.sealed.ciphertextB64Url) as unknown as ArrayBuffer,
    );
    return new Uint8Array(plaintext);
  } finally {
    recordKey.fill(0);
  }
}

async function importAesKey(rawKey: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  if (rawKey.length !== 32) {
    throw new Error('collection record key must be 32 bytes');
  }
  return crypto.subtle.importKey('raw', rawKey as unknown as ArrayBuffer, { name: 'AES-GCM' }, false, usages);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= left[index] ^ right[index];
  }
  return diff === 0;
}
