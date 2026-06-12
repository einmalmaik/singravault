// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Hashes for the operation log: AAD hash, ciphertext hash, op hash
 * and vault head.
 *
 * Every input to a hash goes through `canonicalizeVaultStructure`
 * first. Hashes are SHA-256 (Powered by DIS — Defensive Integration
 * Shield, `@dis/shield/integrity`). The wire form is base64url
 * without padding.
 */

import { sha256Bytes } from '@dis/shield/integrity';
import {
  canonicalizeVaultStructure,
  encodeBase64Url,
} from './canonicalJson';
import {
  RECORD_ENCRYPTION_SCHEMA_V1,
  type RecordAadV1,
  type VaultOperationSignedBodyV1,
} from './types';

const HEAD_SCHEMA_V1 = 'vault-head-v1' as const;
const OP_HASH_SCHEMA_V1 = 'op-hash-v1' as const;
const CIPHERTEXT_HASH_SCHEMA_V1 = 'ciphertext-hash-v1' as const;

/**
 * SHA-256 of the canonical AAD bytes, base64url.
 */
export async function computeAadHash(aad: RecordAadV1): Promise<string> {
  const bytes = canonicalizeVaultStructure(aad);
  return encodeBase64Url(await sha256Bytes(bytes));
}

/**
 * Deterministic hash over the ciphertext envelope plus its binding
 * context. The runtime compares this hash to the `ciphertext_hash`
 * column to detect server-side tampering before any AEAD open is
 * attempted.
 *
 * This hash is NOT a secret. It is a reference/integrity value.
 */
export async function computeCiphertextHash(input: {
  readonly aadHash: string;
  readonly nonceB64Url: string;
  readonly ciphertextB64Url: string;
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: string;
  readonly recordVersion: number;
  readonly keyVersion: number;
}): Promise<string> {
  const payload = {
    schema: CIPHERTEXT_HASH_SCHEMA_V1,
    aadHash: input.aadHash,
    ciphertext: input.ciphertextB64Url,
    encryptionSchema: RECORD_ENCRYPTION_SCHEMA_V1,
    keyVersion: input.keyVersion,
    nonce: input.nonceB64Url,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: input.recordVersion,
    vaultId: input.vaultId,
  };
  const bytes = canonicalizeVaultStructure(payload);
  return encodeBase64Url(await sha256Bytes(bytes));
}

/**
 * `opHash` identifies an operation uniquely. It is the SHA-256 of
 * the canonical signed body without the signature.
 */
export async function computeOpHash(body: VaultOperationSignedBodyV1): Promise<string> {
  const payload = {
    schema: OP_HASH_SCHEMA_V1,
    body,
  };
  const bytes = canonicalizeVaultStructure(payload);
  return encodeBase64Url(await sha256Bytes(bytes));
}

/**
 * `resultingVaultHead = SHA-256(canonical({ previousVaultHead,
 * opHash, recordId, recordType, newRecordHash, opType }))`.
 *
 * Clients persist the last locally verified head as
 * `lastVerifiedVaultHead`. A server-supplied head that is older,
 * unknown or contradicts the local head never triggers a silent
 * rebaseline.
 */
export async function computeVaultHead(input: {
  readonly previousVaultHead: string | null;
  readonly opHash: string;
  readonly recordId: string;
  readonly recordType: string;
  readonly newRecordHash: string | null;
  readonly opType: string;
}): Promise<string> {
  const payload = {
    schema: HEAD_SCHEMA_V1,
    newRecordHash: input.newRecordHash,
    opHash: input.opHash,
    opType: input.opType,
    previousVaultHead: input.previousVaultHead,
    recordId: input.recordId,
    recordType: input.recordType,
  };
  const bytes = canonicalizeVaultStructure(payload);
  return encodeBase64Url(await sha256Bytes(bytes));
}

/**
 * SHA-256 of an arbitrary already-canonicalised byte sequence.
 * Intended for callers that have already produced the canonical
 * bytes elsewhere (e.g. a record payload for `newRecordHash`). Do
 * not feed JS strings to this function; feed bytes.
 */
export async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
  return encodeBase64Url(await sha256Bytes(bytes));
}
