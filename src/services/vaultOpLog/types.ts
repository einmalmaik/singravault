// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Shared public types for the operation-log-based vault integrity
 * layer. Every type here describes a byte-stable on-the-wire or
 * on-disk shape. Do not add fields that are not both signed or hashed
 * and part of the canonical layout.
 *
 * The layout is normative and reflects ADR-0004 and the concept doc
 * in `singra_vault_neues_integrations_quarantaene_konzept.md`.
 */

export const RECORD_AAD_SCHEMA_V1 = 'record-aad-v1' as const;
export const RECORD_ENCRYPTION_SCHEMA_V1 = 'record-aead-v1' as const;
export const DEVICE_SIGNATURE_SCHEMA_V1 = 'device-signature-v1' as const;
export const APP_NAMESPACE = 'singra-vault' as const;

/**
 * The fixed set of record types that may ever appear in a vault
 * record row. Any new type is a protocol change.
 */
export const RECORD_TYPES = [
  'item',
  'category',
  'attachment_metadata',
  'attachment_chunk',
  'manifest',
  'tombstone',
  'device',
] as const;
export type RecordType = (typeof RECORD_TYPES)[number];

export function isRecordType(value: unknown): value is RecordType {
  return typeof value === 'string' && (RECORD_TYPES as readonly string[]).includes(value);
}

/**
 * Operation types. Every mutation is one of these. New types require
 * both a client and server migration.
 */
export const OPERATION_TYPES = [
  'create',
  'update',
  'delete',
  'restore',
  'move',
  'rekey',
  'add_device',
  'revoke_device',
] as const;
export type OperationType = (typeof OPERATION_TYPES)[number];

export function isOperationType(value: unknown): value is OperationType {
  return typeof value === 'string' && (OPERATION_TYPES as readonly string[]).includes(value);
}

/**
 * Canonical AAD v1. This is the structure that is canonicalised and
 * passed to AES-GCM as additional authenticated data.
 */
export interface RecordAadV1 {
  readonly app: typeof APP_NAMESPACE;
  readonly aadSchema: typeof RECORD_AAD_SCHEMA_V1;
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly encryptionSchema: typeof RECORD_ENCRYPTION_SCHEMA_V1;
}

/**
 * Inputs the caller supplies to build a `RecordAadV1`. The schema
 * fields are pinned and cannot be overridden.
 */
export interface BuildRecordAadInput {
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
}

/**
 * The canonical signed body of a vault operation. The signature
 * itself is a separate field on the wire; it is never part of the
 * canonical body.
 *
 * `null` is used for absent fields, never `undefined`. Optional
 * protocol fields that do not apply to an operation type are still
 * present and set to `null`.
 */
export interface VaultOperationSignedBodyV1 {
  readonly signatureSchema: typeof DEVICE_SIGNATURE_SCHEMA_V1;
  readonly opId: string;
  readonly intentId: string;
  readonly rebasedFromOpId: string | null;
  readonly vaultId: string;
  readonly authorDeviceId: string;
  readonly opType: OperationType;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly baseRecordVersion: number | null;
  /**
   * SHA-256 of the record's current `ciphertext_hash` envelope
   * column that the client observed when it built this operation.
   * The server enforces `previousCiphertextHash === vault_records.ciphertext_hash`
   * for every non-create op. It is NOT an operation-level hash
   * chain link: it binds the update to a specific stored ciphertext
   * state, so two concurrent updates based on the same record_version
   * but different observed ciphertext cannot both win.
   */
  readonly previousCiphertextHash: string | null;
  readonly newRecordHash: string | null;
  readonly baseVaultHead: string | null;
  readonly payloadCiphertextHash: string | null;
  readonly payloadAadHash: string | null;
  readonly createdAtClient: string;
  readonly trustEpoch: number;
  /**
   * For `add_device` operations: the SPKI public key (base64url) of the
   * device being added. This field is CRITICAL and MUST be signed
   * to prevent man-in-the-middle attacks where an attacker or
   * compromised server substitutes a different public key.
   *
   * Security Invariant: Without a signed public key, the operation
   * could authorize a device whose private key the attacker controls.
   */
  readonly targetPublicSigningKey?: string | null;
  /**
   * For `add_device` operations: SHA-256 fingerprint of the target
   * public signing key. Provides a quick verification mechanism
   * independent of the full key transmission.
   */
  readonly targetDeviceKeyFingerprint?: string | null;
}

/**
 * An operation as it is passed between services. Contains both the
 * canonical signed body and the separate signature output. The
 * signature is base64url-encoded raw bytes.
 */
export interface SignedVaultOperationV1 {
  readonly body: VaultOperationSignedBodyV1;
  readonly signature: string;
  readonly opHash: string;
}

/**
 * Trusted device record as stored in the vault trust list. The
 * runtime never signs with anything but the matching device key.
 */
export interface TrustedDeviceRecordV1 {
  readonly vaultId: string;
  readonly deviceId: string;
  readonly publicSigningKey: string;
  readonly deviceNameEncrypted: string;
  readonly addedByDeviceId: string | null;
  readonly addedAt: string;
  readonly trustEpoch: number;
  readonly status: 'trusted' | 'revoked';
  readonly revokedAt: string | null;
  readonly revokedByDeviceId: string | null;
}

/**
 * Author classification result for an operation. Only `trusted`
 * lets the operation advance the state machine.
 */
export type AuthorTrustClassification =
  | {
      readonly status: 'trusted';
      readonly device: TrustedDeviceRecordV1;
    }
  | {
      readonly status: 'revoked';
      readonly device: TrustedDeviceRecordV1;
      readonly reason: 'revoked_before_op';
    }
  | {
      readonly status: 'unknown';
      readonly reason:
        | 'device_not_in_trust_list'
        | 'device_trust_epoch_mismatch'
        | 'device_wrong_vault';
    };

/**
 * Result of a record-key derivation. The raw bytes live on a
 * `SecureBuffer`-like surface so the caller can wipe them. Callers
 * must not persist `keyMaterial`.
 */
export interface DerivedRecordKeyV1 {
  readonly keyId: string;
  readonly keyVersion: number;
  readonly keyMaterial: Uint8Array;
}

/**
 * A sealed record as produced by `cryptoRecordService`. This is what
 * is pushed into `submit_vault_operation` alongside the operation.
 */
export interface SealedRecordV1 {
  readonly aad: RecordAadV1;
  readonly aadHash: string;
  readonly nonceB64Url: string;
  readonly ciphertextB64Url: string;
  readonly ciphertextHash: string;
}

/**
 * An opened record. Contains only the plaintext bytes and the
 * verified metadata. Callers that need to render it must enforce the
 * plaintext lifecycle rules from ADR-0004.
 */
export interface OpenedRecordV1 {
  readonly plaintext: Uint8Array;
  readonly aad: RecordAadV1;
}

export type VaultCanonicalizationErrorCode =
  | 'undefined_not_allowed'
  | 'non_finite_number'
  | 'bigint_not_allowed'
  | 'symbol_not_allowed'
  | 'function_not_allowed'
  | 'cyclic_reference'
  | 'unsupported_value';

export class VaultCanonicalizationError extends Error {
  public readonly code: VaultCanonicalizationErrorCode;
  public readonly path: ReadonlyArray<string | number>;
  constructor(code: VaultCanonicalizationErrorCode, path: ReadonlyArray<string | number>) {
    super(`vault canonicalization failed: ${code} at /${path.join('/')}`);
    this.code = code;
    this.path = path;
    this.name = 'VaultCanonicalizationError';
  }
}

export type VaultCryptoErrorCode =
  | 'aead_decryption_failed'
  | 'aad_hash_mismatch'
  | 'ciphertext_hash_mismatch'
  | 'unexpected_record_context'
  | 'key_material_invalid'
  | 'base64url_invalid'
  | 'record_type_invalid'
  | 'schema_version_unsupported';

export class VaultCryptoError extends Error {
  public readonly code: VaultCryptoErrorCode;
  constructor(code: VaultCryptoErrorCode, message?: string) {
    super(message ?? code);
    this.code = code;
    this.name = 'VaultCryptoError';
  }
}

export type VaultSignatureErrorCode =
  | 'invalid_signature'
  | 'op_hash_mismatch'
  | 'signed_body_invalid'
  | 'signature_format_invalid'
  | 'public_key_format_invalid';

export class VaultSignatureError extends Error {
  public readonly code: VaultSignatureErrorCode;
  constructor(code: VaultSignatureErrorCode, message?: string) {
    super(message ?? code);
    this.code = code;
    this.name = 'VaultSignatureError';
  }
}
