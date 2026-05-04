// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Canonical AAD v1 builder and comparator.
 *
 * AAD (Additional Authenticated Data) is passed into AES-GCM to bind
 * a ciphertext to its exact record context. A ciphertext encrypted
 * for record `foo` in vault `A` at version `3` cannot be opened as
 * record `bar` in vault `B` at version `3`, and cannot be opened as
 * any other record version or type, because the AAD would mismatch
 * and the AEAD authentication tag would not verify.
 */

import {
  canonicalizeVaultStructure,
  constantTimeEquals,
} from './canonicalJson';
import {
  APP_NAMESPACE,
  RECORD_AAD_SCHEMA_V1,
  RECORD_ENCRYPTION_SCHEMA_V1,
  VaultCryptoError,
  isRecordType,
  type BuildRecordAadInput,
  type RecordAadV1,
} from './types';

/**
 * Build a canonical `RecordAadV1` from caller inputs. The `app`,
 * `aadSchema` and `encryptionSchema` fields are pinned and cannot be
 * overridden. Negative or non-integer versions are rejected.
 */
export function buildRecordAad(input: BuildRecordAadInput): RecordAadV1 {
  if (!isRecordType(input.recordType)) {
    throw new VaultCryptoError('record_type_invalid', `unknown record type: ${String(input.recordType)}`);
  }
  if (!isSafeNonNegativeInteger(input.recordVersion)) {
    throw new VaultCryptoError('schema_version_unsupported', 'recordVersion must be a non-negative safe integer');
  }
  if (!isSafeNonNegativeInteger(input.keyVersion)) {
    throw new VaultCryptoError('schema_version_unsupported', 'keyVersion must be a non-negative safe integer');
  }
  if (typeof input.vaultId !== 'string' || input.vaultId.length === 0) {
    throw new VaultCryptoError('schema_version_unsupported', 'vaultId must be a non-empty string');
  }
  if (typeof input.recordId !== 'string' || input.recordId.length === 0) {
    throw new VaultCryptoError('schema_version_unsupported', 'recordId must be a non-empty string');
  }
  return {
    app: APP_NAMESPACE,
    aadSchema: RECORD_AAD_SCHEMA_V1,
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: input.recordVersion,
    keyVersion: input.keyVersion,
    encryptionSchema: RECORD_ENCRYPTION_SCHEMA_V1,
  };
}

/**
 * Produce the canonical UTF-8 byte representation of a `RecordAadV1`.
 * This is exactly what AES-GCM authenticates and what is hashed to
 * produce `aadHash`.
 */
export function encodeRecordAadBytes(aad: RecordAadV1): Uint8Array {
  return canonicalizeVaultStructure(aad);
}

/**
 * Byte-equality test for two AADs. This is what the runtime uses to
 * decide whether an incoming record's AAD matches what the state
 * machine expects. Constant-time over the byte overlap.
 */
export function recordAadsEqual(left: RecordAadV1, right: RecordAadV1): boolean {
  return constantTimeEquals(
    canonicalizeVaultStructure(left),
    canonicalizeVaultStructure(right),
  );
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
