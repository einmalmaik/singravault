// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `operationSigningService` — canonicalise, sign and verify vault
 * operations.
 *
 * v1 uses WebCrypto ECDSA over P-256 with SHA-256. Public keys are
 * stored as SPKI bytes, base64url-encoded, in the vault device trust
 * list. Private keys are generated with `extractable: false` so
 * they never leave the device.
 *
 * Signatures are computed over the SHA-256 of the canonical signed
 * body. The signature wire form is the raw r||s concatenation as
 * produced by WebCrypto's `ECDSA` signer, base64url-encoded.
 */

import {
  canonicalizeVaultStructure,
  decodeBase64Url,
  encodeBase64Url,
} from './canonicalJson';
import {
  computeOpHash,
} from './recordHashes';
import {
  DEVICE_SIGNATURE_SCHEMA_V2,
  DEVICE_SIGNATURE_SCHEMA_V1,
  VaultSignatureError,
  type DeviceSignatureSchema,
  isOperationType,
  isRecordType,
  type OperationType,
  type RecordType,
  type SignedVaultOperationV1,
  type VaultOperationSignedBodyV1,
} from './types';

const SIGNING_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGNING_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;
const SIGNATURE_RAW_LENGTH = 64;

export interface DeviceSigningKeyPair {
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly publicKeyB64Url: string;
}

/**
 * Generate a fresh non-exportable ECDSA P-256 key pair for a device
 * and return both the key handles and the base64url-encoded SPKI
 * public key that will be persisted in the vault trust list.
 */
export async function generateDeviceSigningKeyPair(): Promise<DeviceSigningKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    SIGNING_ALGORITHM,
    /* extractable */ false,
    ['sign', 'verify'],
  );
  const exportablePublic = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyB64Url = encodeBase64Url(new Uint8Array(exportablePublic));
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyB64Url,
  };
}

/**
 * Import a stored SPKI public key from its base64url wire form.
 */
export async function importDevicePublicKey(publicKeyB64Url: string): Promise<CryptoKey> {
  let spkiBytes: Uint8Array;
  try {
    spkiBytes = decodeBase64Url(publicKeyB64Url);
  } catch {
    throw new VaultSignatureError('public_key_format_invalid', 'public key is not valid base64url');
  }
  try {
    return await crypto.subtle.importKey(
      'spki',
      spkiBytes as unknown as ArrayBuffer,
      SIGNING_ALGORITHM,
      false,
      ['verify'],
    );
  } catch {
    throw new VaultSignatureError('public_key_format_invalid', 'public key SPKI import failed');
  }
}

/**
 * Inputs to build a canonical signed body. All required fields of
 * `VaultOperationSignedBodyV1` are present; the `signatureSchema`
 * is pinned.
 */
export interface BuildOperationBodyInput {
  readonly signatureSchema?: DeviceSignatureSchema;
  readonly opId: string;
  /**
   * Stable logical-intent identifier. A retry after a `stale_vault_head`
   * conflict reuses the same `intentId` with a fresh `opId`, fresh
   * `rebasedFromOpId` and a fresh signature. The server never
   * interprets `intentId`; clients use it to deduplicate their own
   * retries.
   */
  readonly intentId: string;
  /**
   * `null` for a first submission. On rebase-and-retry, set to the
   * `opId` of the previous (now stale) attempt. Both fields enter the
   * canonical body and therefore bind the rebase chain to the
   * signature.
   */
  readonly rebasedFromOpId: string | null;
  readonly vaultId: string;
  readonly authorDeviceId: string;
  readonly opType: OperationType;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly baseRecordVersion: number | null;
  /**
   * SHA-256 of the record's current `ciphertext_hash` column that
   * the client observed when it built this operation. See the field
   * JSDoc on `VaultOperationSignedBodyV1.previousCiphertextHash` for
   * the exact binding.
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
   * device being added. CRITICAL: This must be signed to prevent MITM.
   * Must be `null` for all other operation types.
   */
  readonly targetPublicSigningKey?: string | null;
  /**
   * For `add_device` operations: SHA-256 fingerprint of the target key.
   * Must be `null` for all other operation types.
   */
  readonly targetDeviceKeyFingerprint?: string | null;
  readonly recoveryCodeSetId?: string | null;
  readonly recoveryCodeCommitments?: readonly string[] | null;
  readonly recoveryCodeCommitment?: string | null;
}

/**
 * Build a canonical signed body from caller inputs. Validates types,
 * but does not enforce op-type-to-record-type consistency — that is
 * the state machine's job in a later phase.
 */
export function buildOperationSignedBody(input: BuildOperationBodyInput): VaultOperationSignedBodyV1 {
  const signatureSchema = input.signatureSchema
    ?? (isRecoveryOperationType(input.opType) ? DEVICE_SIGNATURE_SCHEMA_V2 : DEVICE_SIGNATURE_SCHEMA_V1);
  if (!isOperationType(input.opType)) {
    throw new VaultSignatureError('signed_body_invalid', `unknown opType: ${String(input.opType)}`);
  }
  if (!isRecordType(input.recordType)) {
    throw new VaultSignatureError('signed_body_invalid', `unknown recordType: ${String(input.recordType)}`);
  }
  if (!Number.isSafeInteger(input.trustEpoch) || input.trustEpoch < 0) {
    throw new VaultSignatureError('signed_body_invalid', 'trustEpoch must be a non-negative safe integer');
  }
  if (input.baseRecordVersion !== null && (!Number.isSafeInteger(input.baseRecordVersion) || input.baseRecordVersion < 0)) {
    throw new VaultSignatureError('signed_body_invalid', 'baseRecordVersion must be null or non-negative safe integer');
  }
  if (typeof input.createdAtClient !== 'string' || !isIsoInstant(input.createdAtClient)) {
    throw new VaultSignatureError('signed_body_invalid', 'createdAtClient must be an ISO-8601 UTC instant');
  }
  if (typeof input.intentId !== 'string' || input.intentId.length === 0) {
    throw new VaultSignatureError('signed_body_invalid', 'intentId must be a non-empty string');
  }
  if (input.rebasedFromOpId !== null
      && (typeof input.rebasedFromOpId !== 'string' || input.rebasedFromOpId.length === 0)) {
    throw new VaultSignatureError('signed_body_invalid', 'rebasedFromOpId must be null or a non-empty string');
  }
  if (input.rebasedFromOpId !== null && input.rebasedFromOpId === input.opId) {
    throw new VaultSignatureError('signed_body_invalid', 'rebasedFromOpId must differ from opId');
  }

  if (signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V1 && signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V2) {
    throw new VaultSignatureError('signed_body_invalid', 'unknown signatureSchema');
  }
  if (signatureSchema === DEVICE_SIGNATURE_SCHEMA_V1 && isRecoveryOperationType(input.opType)) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery operations require device-signature-v2');
  }
  if (signatureSchema === DEVICE_SIGNATURE_SCHEMA_V1 && hasRecoveryFields(input)) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery fields require device-signature-v2');
  }

  // SECURITY: For add_device/recover_device operations, targetPublicSigningKey MUST be signed.
  // An absent or null public key is a security vulnerability.
  if (input.opType === 'add_device' || input.opType === 'recover_device') {
    if (input.targetPublicSigningKey === undefined || input.targetPublicSigningKey === null) {
      throw new VaultSignatureError(
        'signed_body_invalid',
        `${input.opType} operation requires targetPublicSigningKey to be signed`,
      );
    }
    // targetDeviceKeyFingerprint is optional but recommended
  } else {
    // For non-add_device operations, these must be null
    if (input.targetPublicSigningKey !== undefined && input.targetPublicSigningKey !== null) {
      throw new VaultSignatureError(
        'signed_body_invalid',
        'targetPublicSigningKey is only valid for add_device or recover_device operations',
      );
    }
    if (input.targetDeviceKeyFingerprint !== undefined && input.targetDeviceKeyFingerprint !== null) {
      throw new VaultSignatureError(
        'signed_body_invalid',
        'targetDeviceKeyFingerprint is only valid for add_device or recover_device operations',
      );
    }
  }

  if (input.opType === 'recovery_codes_rotate') {
    if (!input.recoveryCodeSetId) {
      throw new VaultSignatureError('signed_body_invalid', 'recovery_codes_rotate requires recoveryCodeSetId');
    }
    if (!Array.isArray(input.recoveryCodeCommitments) || input.recoveryCodeCommitments.length === 0) {
      throw new VaultSignatureError('signed_body_invalid', 'recovery_codes_rotate requires commitments');
    }
    if (input.recoveryCodeCommitments.length > 5) {
      throw new VaultSignatureError('signed_body_invalid', 'recovery_codes_rotate supports at most five commitments');
    }
    if (input.recoveryCodeCommitments.some((commitment) => typeof commitment !== 'string' || commitment.length === 0)) {
      throw new VaultSignatureError('signed_body_invalid', 'recovery code commitments must be non-empty strings');
    }
    if (input.recoveryCodeCommitment !== undefined && input.recoveryCodeCommitment !== null) {
      throw new VaultSignatureError('signed_body_invalid', 'single recovery commitment is only valid for recover_device');
    }
  } else if (input.opType === 'recover_device') {
    if (!input.recoveryCodeSetId || !input.recoveryCodeCommitment) {
      throw new VaultSignatureError('signed_body_invalid', 'recover_device requires recovery code set and commitment');
    }
    if (input.recoveryCodeCommitments !== undefined && input.recoveryCodeCommitments !== null) {
      throw new VaultSignatureError('signed_body_invalid', 'commitment list is only valid for recovery_codes_rotate');
    }
  } else if (hasRecoveryFields(input)) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery fields are only valid for recovery operations');
  }

  const baseBody: VaultOperationSignedBodyV1 = {
    signatureSchema,
    opId: input.opId,
    intentId: input.intentId,
    rebasedFromOpId: input.rebasedFromOpId,
    vaultId: input.vaultId,
    authorDeviceId: input.authorDeviceId,
    opType: input.opType,
    recordId: input.recordId,
    recordType: input.recordType,
    baseRecordVersion: input.baseRecordVersion,
    previousCiphertextHash: input.previousCiphertextHash,
    newRecordHash: input.newRecordHash,
    baseVaultHead: input.baseVaultHead,
    payloadCiphertextHash: input.payloadCiphertextHash,
    payloadAadHash: input.payloadAadHash,
    createdAtClient: input.createdAtClient,
    trustEpoch: input.trustEpoch,
    targetPublicSigningKey: input.targetPublicSigningKey ?? null,
    targetDeviceKeyFingerprint: input.targetDeviceKeyFingerprint ?? null,
  };

  if (signatureSchema === DEVICE_SIGNATURE_SCHEMA_V2) {
    return {
      ...baseBody,
      recoveryCodeSetId: input.recoveryCodeSetId ?? null,
      recoveryCodeCommitments: input.recoveryCodeCommitments ?? null,
      recoveryCodeCommitment: input.recoveryCodeCommitment ?? null,
    };
  }

  return baseBody;
}

/**
 * Produce a `SignedVaultOperationV1` from a canonical body and a
 * private key. The signature is computed over the canonical bytes
 * of the body; the `opHash` is computed from the same canonicalised
 * body and is returned alongside the signature for easy routing.
 */
export async function signOperation(
  body: VaultOperationSignedBodyV1,
  privateKey: CryptoKey,
): Promise<SignedVaultOperationV1> {
  const bytes = canonicalizeVaultStructure(body);
  const signatureBuffer = await crypto.subtle.sign(
    SIGNING_PARAMS,
    privateKey,
    bytes as unknown as ArrayBuffer,
  );
  const signatureBytes = new Uint8Array(signatureBuffer);
  if (signatureBytes.length !== SIGNATURE_RAW_LENGTH) {
    throw new VaultSignatureError('signature_format_invalid', 'unexpected ECDSA signature byte length');
  }
  const signature = encodeBase64Url(signatureBytes);
  const opHash = await computeOpHash(body);
  return { body, signature, opHash };
}

/**
 * Verify a signed operation against a public key. Returns `true` if
 * the signature is valid AND the `opHash` on the signed-operation
 * envelope matches the body. Returns `false` for a wrong signature.
 * Throws `VaultSignatureError` if the signature byte form or the
 * `opHash` are structurally wrong.
 */
export async function verifyOperationSignature(
  signed: SignedVaultOperationV1,
  publicKey: CryptoKey,
): Promise<boolean> {
  if (
    signed.body.signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V1
    && signed.body.signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V2
  ) {
    throw new VaultSignatureError('signed_body_invalid', 'unknown signatureSchema');
  }
  const recomputedOpHash = await computeOpHash(signed.body);
  if (recomputedOpHash !== signed.opHash) {
    throw new VaultSignatureError('op_hash_mismatch', 'opHash does not match canonical body');
  }
  let signatureBytes: Uint8Array;
  try {
    signatureBytes = decodeBase64Url(signed.signature);
  } catch {
    throw new VaultSignatureError('signature_format_invalid', 'signature is not valid base64url');
  }
  if (signatureBytes.length !== SIGNATURE_RAW_LENGTH) {
    throw new VaultSignatureError('signature_format_invalid', 'unexpected ECDSA signature byte length');
  }
  const bytes = canonicalizeVaultStructure(signed.body);
  try {
    return await crypto.subtle.verify(
      SIGNING_PARAMS,
      publicKey,
      signatureBytes as unknown as ArrayBuffer,
      bytes as unknown as ArrayBuffer,
    );
  } catch {
    return false;
  }
}

export async function doesDeviceSigningKeyMatchPublicKey(
  privateKey: CryptoKey,
  publicKeyB64Url: string,
): Promise<boolean> {
  const publicKey = await importDevicePublicKey(publicKeyB64Url);
  const challenge = canonicalizeVaultStructure({
    app: 'singra-vault',
    purpose: 'oplog-device-signing-key-possession-check-v1',
  });
  const signatureBuffer = await crypto.subtle.sign(
    SIGNING_PARAMS,
    privateKey,
    challenge as unknown as ArrayBuffer,
  );

  return crypto.subtle.verify(
    SIGNING_PARAMS,
    publicKey,
    signatureBuffer,
    challenge as unknown as ArrayBuffer,
  );
}

function isIsoInstant(value: string): boolean {
  // Accept ISO-8601 UTC instants with or without fractional seconds.
  // Example: 2026-05-02T10:30:00.000Z
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/u.test(value);
}

function isRecoveryOperationType(opType: OperationType): boolean {
  return opType === 'recovery_codes_rotate' || opType === 'recover_device';
}

function hasRecoveryFields(input: BuildOperationBodyInput): boolean {
  return (input.recoveryCodeSetId !== undefined && input.recoveryCodeSetId !== null)
    || (input.recoveryCodeCommitments !== undefined && input.recoveryCodeCommitments !== null)
    || (input.recoveryCodeCommitment !== undefined && input.recoveryCodeCommitment !== null);
}
