// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `verifyOperation` — cryptographically verify a remote operation
 * before any record is decrypted.
 *
 * This module is the first gate in the Phase 5 pipeline.
 * It re-canonicalises, re-hashes and verifies the signature of a
 * `VaultOperationRow` against a stored device public key and the
 * vault trust list.
 *
 * No decryption happens here. No plaintext is produced.
 */

import {
  classifyOperationAuthor,
  type TrustListInput,
} from './deviceTrustService';
import {
  importDevicePublicKey,
  verifyOperationSignature,
} from './operationSigningService';
import {
  canRecoverDeviceFromCodeSet,
  type RecoveryCodeTrustInput,
} from './recoveryCodeTrustService';
import {
  computeOpHash,
} from './recordHashes';
import {
  DEVICE_SIGNATURE_SCHEMA_V2,
  DEVICE_SIGNATURE_SCHEMA_V1,
  isOperationType,
  isRecordType,
  type SignedVaultOperationV1,
  type VaultOperationSignedBodyV1,
} from './types';
import type {
  OperationVerificationResult,
} from './vaultSecurityStates';
import type {
  VaultOperationRow,
} from './vaultOpLogRpcTypes';

export interface VerifyOperationInput {
  readonly operation: VaultOperationRow;
  readonly trust: TrustListInput;
  readonly recoveryTrust?: RecoveryCodeTrustInput;
  readonly publicKey?: CryptoKey;
  /**
   * Optional local record state for causal checks. If omitted,
   * only syntactic validation is performed.
   */
  readonly localRecordState?: {
    readonly recordVersion: number;
    readonly ciphertextHash: string;
  } | null;
}

/**
 * Verify an operation from the repository layer.
 *
 * Steps:
 * 1. Parse and validate the `signedBody` into a canonical shape.
 * 2. Recompute `opHash` and compare.
 * 3. Verify ECDSA signature over the canonical body.
 * 4. Classify the author against the vault trust list.
 * 5. Validate operation-type-specific field constraints.
 * 6. Optionally check causal consistency against local record state.
 */
export async function verifyOperation(
  input: VerifyOperationInput,
): Promise<OperationVerificationResult> {
  const { operation, trust, localRecordState } = input;

  // Step 1: parse signed body
  const body = extractSignedBody(operation.signedBody);
  if (body === null) {
    return { kind: 'requiresLockedCritical' };
  }

  const signedOp: SignedVaultOperationV1 = {
    body,
    signature: operation.signature,
    opHash: operation.opHash,
  };

  // Step 2: opHash verification
  let recomputedOpHash: string;
  try {
    recomputedOpHash = await computeOpHash(body);
  } catch {
    return { kind: 'opHashMismatch' };
  }
  if (recomputedOpHash !== operation.opHash) {
    return { kind: 'opHashMismatch' };
  }

  if (body.opType === 'recover_device') {
    const opTypeCheck = validateOperationTypeConstraints(body);
    if (opTypeCheck !== null) {
      return opTypeCheck;
    }
    const signedRecoverOp: SignedVaultOperationV1 = {
      body,
      signature: operation.signature,
      opHash: operation.opHash,
    };
    if (
      !input.recoveryTrust
      || !canRecoverDeviceFromCodeSet(signedRecoverOp, input.recoveryTrust)
    ) {
      return { kind: 'unknownAuthor', reason: 'recovery_code_set_not_trusted' };
    }

    let signatureValid: boolean;
    try {
      const publicKey = input.publicKey ?? await importDevicePublicKey(body.targetPublicSigningKey ?? '');
      signatureValid = await verifyOperationSignature(signedRecoverOp, publicKey);
    } catch {
      return { kind: 'invalidSignature' };
    }
    if (!signatureValid) {
      return { kind: 'invalidSignature' };
    }

    if (localRecordState !== undefined) {
      const causal = checkCausalConsistency(body, localRecordState);
      if (causal !== null) {
        return causal;
      }
    }

    return { kind: 'validTrustedOperation', signedOperation: signedRecoverOp };
  }

  // Step 3: author trust classification. This must happen before signature
  // verification so the signature is checked with the author's public key,
  // not with the current local device key.
  const author = classifyOperationAuthor(signedOp, trust);
  if (author.status === 'unknown') {
    return { kind: 'unknownAuthor', reason: author.reason };
  }
  if (author.status === 'revoked') {
    return { kind: 'revokedAuthor', device: author.device, reason: author.reason };
  }

  // Step 4: signature verification
  let signatureValid: boolean;
  try {
    const publicKey = input.publicKey ?? await importDevicePublicKey(author.device.publicSigningKey);
    signatureValid = await verifyOperationSignature(signedOp, publicKey);
  } catch {
    return { kind: 'invalidSignature' };
  }
  if (!signatureValid) {
    return { kind: 'invalidSignature' };
  }

  // Step 5: operation-type syntactic validation
  const opTypeCheck = validateOperationTypeConstraints(body);
  if (opTypeCheck !== null) {
    return opTypeCheck;
  }

  // Step 6: causal / consistency check against local state
  if (localRecordState !== undefined) {
    const causal = checkCausalConsistency(body, localRecordState);
    if (causal !== null) {
      return causal;
    }
  }

  return { kind: 'validTrustedOperation', signedOperation: signedOp };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract and structurally validate the `signedBody` field of a DB
 * operation row. Returns `null` if the body is malformed.
 *
 * Every field of `VaultOperationSignedBodyV1` is checked for presence
 * and type. No semantic validation (epoch ranges, ISO dates) is done
 * here — that belongs to the signing service which validates during
 * `buildOperationSignedBody` and indirectly during canonicalisation.
 */
function extractSignedBody(raw: unknown): VaultOperationSignedBodyV1 | null {
  if (raw === null || typeof raw !== 'object') {
    return null;
  }
  const obj = raw as Record<string, unknown>;

  const signatureSchema = expectString(obj, 'signatureSchema');
  if (signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V1 && signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V2) {
    return null;
  }

  const opId = expectString(obj, 'opId');
  const intentId = expectString(obj, 'intentId');
  const rebasedFromOpId = expectStringOrNull(obj, 'rebasedFromOpId');
  const vaultId = expectString(obj, 'vaultId');
  const authorDeviceId = expectString(obj, 'authorDeviceId');
  const opType = expectString(obj, 'opType');
  const recordId = expectString(obj, 'recordId');
  const recordType = expectString(obj, 'recordType');
  const baseRecordVersion = expectNumberOrNull(obj, 'baseRecordVersion');
  const previousCiphertextHash = expectStringOrNull(obj, 'previousCiphertextHash');
  const newRecordHash = expectStringOrNull(obj, 'newRecordHash');
  const baseVaultHead = expectStringOrNull(obj, 'baseVaultHead');
  const payloadCiphertextHash = expectStringOrNull(obj, 'payloadCiphertextHash');
  const payloadAadHash = expectStringOrNull(obj, 'payloadAadHash');
  const createdAtClient = expectString(obj, 'createdAtClient');
  const trustEpoch = expectSafeInteger(obj, 'trustEpoch');
  if (
    opId === null ||
    intentId === null ||
    vaultId === null ||
    authorDeviceId === null ||
    opType === null ||
    recordId === null ||
    recordType === null ||
    createdAtClient === null ||
    trustEpoch === null
  ) {
    return null;
  }

  if (!isOperationType(opType)) {
    return null;
  }
  if (!isRecordType(recordType)) {
    return null;
  }

  const body: VaultOperationSignedBodyV1 = {
    signatureSchema,
    opId,
    intentId,
    rebasedFromOpId,
    vaultId,
    authorDeviceId,
    opType,
    recordId,
    recordType,
    baseRecordVersion,
    previousCiphertextHash,
    newRecordHash,
    baseVaultHead,
    payloadCiphertextHash,
    payloadAadHash,
    createdAtClient,
    trustEpoch,
  };
  if (Object.prototype.hasOwnProperty.call(obj, 'targetPublicSigningKey')) {
    const targetPublicSigningKey = expectStringOrNull(obj, 'targetPublicSigningKey');
    if (targetPublicSigningKey === null && obj.targetPublicSigningKey !== null) {
      return null;
    }
    body.targetPublicSigningKey = targetPublicSigningKey;
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'targetDeviceKeyFingerprint')) {
    const targetDeviceKeyFingerprint = expectStringOrNull(obj, 'targetDeviceKeyFingerprint');
    if (targetDeviceKeyFingerprint === null && obj.targetDeviceKeyFingerprint !== null) {
      return null;
    }
    body.targetDeviceKeyFingerprint = targetDeviceKeyFingerprint;
  }
  if (signatureSchema === DEVICE_SIGNATURE_SCHEMA_V2) {
    if (Object.prototype.hasOwnProperty.call(obj, 'recoveryCodeSetId')) {
      const recoveryCodeSetId = expectStringOrNull(obj, 'recoveryCodeSetId');
      if (recoveryCodeSetId === null && obj.recoveryCodeSetId !== null) {
        return null;
      }
      body.recoveryCodeSetId = recoveryCodeSetId;
    }
    if (Object.prototype.hasOwnProperty.call(obj, 'recoveryCodeCommitments')) {
      const recoveryCodeCommitments = expectStringArrayOrNull(obj, 'recoveryCodeCommitments');
      if (recoveryCodeCommitments === null && obj.recoveryCodeCommitments !== null) {
        return null;
      }
      body.recoveryCodeCommitments = recoveryCodeCommitments;
    }
    if (Object.prototype.hasOwnProperty.call(obj, 'recoveryCodeCommitment')) {
      const recoveryCodeCommitment = expectStringOrNull(obj, 'recoveryCodeCommitment');
      if (recoveryCodeCommitment === null && obj.recoveryCodeCommitment !== null) {
        return null;
      }
      body.recoveryCodeCommitment = recoveryCodeCommitment;
    }
  }

  return body;
}

function validateOperationTypeConstraints(
  body: VaultOperationSignedBodyV1,
): OperationVerificationResult | null {
  switch (body.opType) {
    case 'create': {
      if (body.baseRecordVersion !== null || body.previousCiphertextHash !== null) {
        return { kind: 'unsupportedOperationType' };
      }
      if (body.newRecordHash === null || body.payloadCiphertextHash === null || body.payloadAadHash === null) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    case 'update':
    case 'restore': {
      if (body.baseRecordVersion === null || body.previousCiphertextHash === null) {
        return { kind: 'unsupportedOperationType' };
      }
      if (body.newRecordHash === null || body.payloadCiphertextHash === null || body.payloadAadHash === null) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    case 'delete': {
      if (body.baseRecordVersion === null || body.previousCiphertextHash === null) {
        return { kind: 'unsupportedOperationType' };
      }
      if (body.newRecordHash === null || body.payloadCiphertextHash === null || body.payloadAadHash === null) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    case 'move':
    case 'rekey':
    case 'revoke_device': {
      // These are currently allowed through syntactic validation.
      // Semantic validation for device-trust ops lives in
      // `deviceTrustService.applyDeviceTrustOperation`.
      if ((body.targetPublicSigningKey ?? null) !== null || (body.targetDeviceKeyFingerprint ?? null) !== null) {
        return { kind: 'unsupportedOperationType' };
      }
      break;
    }
    case 'add_device': {
      if (body.recordType !== 'device') {
        return { kind: 'unsupportedOperationType' };
      }
      if (
        body.baseRecordVersion !== null
        || body.previousCiphertextHash !== null
        || body.newRecordHash !== null
        || body.payloadCiphertextHash !== null
        || body.payloadAadHash !== null
      ) {
        return { kind: 'unsupportedOperationType' };
      }
      if ((body.targetPublicSigningKey ?? null) === null) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    case 'recovery_codes_rotate': {
      if (body.signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V2 || body.recordType !== 'manifest') {
        return { kind: 'unsupportedOperationType' };
      }
      if (
        body.baseRecordVersion !== null
        || body.previousCiphertextHash !== null
        || body.newRecordHash !== null
        || body.payloadCiphertextHash !== null
        || body.payloadAadHash !== null
        || (body.targetPublicSigningKey ?? null) !== null
        || (body.targetDeviceKeyFingerprint ?? null) !== null
        || (body.recoveryCodeCommitment ?? null) !== null
      ) {
        return { kind: 'unsupportedOperationType' };
      }
      const commitments = body.recoveryCodeCommitments ?? null;
      if (
        !body.recoveryCodeSetId
        || body.recordId !== body.recoveryCodeSetId
        || !Array.isArray(commitments)
        || commitments.length === 0
        || commitments.length > 5
        || new Set(commitments).size !== commitments.length
      ) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    case 'recover_device': {
      if (body.signatureSchema !== DEVICE_SIGNATURE_SCHEMA_V2 || body.recordType !== 'device') {
        return { kind: 'unsupportedOperationType' };
      }
      if (
        body.baseRecordVersion !== null
        || body.previousCiphertextHash !== null
        || body.newRecordHash !== null
        || body.payloadCiphertextHash !== null
        || body.payloadAadHash !== null
        || (body.recoveryCodeCommitments ?? null) !== null
      ) {
        return { kind: 'unsupportedOperationType' };
      }
      if (
        (body.targetPublicSigningKey ?? null) === null
        || !body.recoveryCodeSetId
        || !body.recoveryCodeCommitment
        || body.recordId !== body.authorDeviceId
      ) {
        return { kind: 'payloadHashMismatch' };
      }
      break;
    }
    default: {
      return { kind: 'unsupportedOperationType' };
    }
  }
  return null;
}

function checkCausalConsistency(
  body: VaultOperationSignedBodyV1,
  localRecordState: { readonly recordVersion: number; readonly ciphertextHash: string } | null,
): OperationVerificationResult | null {
  if (body.opType === 'create') {
    if (localRecordState !== null) {
      // A create on an already-existing record is a conflict candidate.
      return { kind: 'conflictCandidate' };
    }
    return null;
  }

  if (body.opType === 'update' || body.opType === 'delete' || body.opType === 'restore') {
    if (localRecordState === null) {
      // Updating / deleting a record that does not exist locally is a gap.
      return { kind: 'causalGap' };
    }
    if (body.baseRecordVersion !== localRecordState.recordVersion) {
      return { kind: 'conflictCandidate' };
    }
    if (body.previousCiphertextHash !== localRecordState.ciphertextHash) {
      return { kind: 'rollbackSuspected' };
    }
    return null;
  }

  // move, rekey, add_device, revoke_device and recovery control ops:
  // no local record causal check.
  return null;
}

// ---------------------------------------------------------------------------
// Structural extraction helpers (return null on mismatch)
// ---------------------------------------------------------------------------

function expectString(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  if (typeof value !== 'string') {
    return null;
  }
  return value;
}

function expectStringOrNull(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return null;
  }
  return value;
}

function expectNumberOrNull(obj: Record<string, unknown>, key: string): number | null {
  const value = obj[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }
  return value;
}

function expectStringArrayOrNull(obj: Record<string, unknown>, key: string): readonly string[] | null {
  const value = obj[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    return null;
  }
  return value;
}

function expectSafeInteger(obj: Record<string, unknown>, key: string): number | null {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    return null;
  }
  return value;
}
