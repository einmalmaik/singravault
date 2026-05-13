// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Mappers between Supabase DB/RPC shapes and domain types.
 *
 * Responsibilities:
 * - DB row -> domain row: validate field presence, coerce types, preserve
 *   every security-relevant field.
 * - Domain -> RPC request: translate camelCase domain types into the exact
 *   snake_case JSONB shapes the RPC expects.
 * - `signed_body` is parsed but NOT trusted.  The repository layer merely
 *   transports it; signature/hash verification is Phase 5.
 *
 * Invariants:
 * - Missing mandatory fields cause `VaultOpLogMapperError`, never silent
 *   default values.
 * - Unknown fields that are not security-relevant do not break parsing, but
 *   security-relevant fields must never be lost.
 * - `null` in the DB is preserved as `null`; it is not converted to
 *   `undefined`.
 */

import {
  isOperationType,
  isRecordType,
  type OperationType,
  type RecordType,
} from './types';
import type {
  DbVaultHeadRow,
  DbVaultOperationRow,
  DbVaultRecordRow,
  RpcBootstrapVaultTrustRequest,
  RpcGetVaultChangesSinceRequest,
  RpcGetVaultHeadRequest,
  RpcGetVaultRecordsByIdsRequest,
  RpcSubmitVaultOperationRequest,
  VaultHeadRow,
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';

export class VaultOpLogMapperError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultOpLogMapperError';
  }
}

// ---------------------------------------------------------------------------
// DB -> Domain
// ---------------------------------------------------------------------------

/**
 * Map a raw DB operation row to the domain type.
 * Validates every security-relevant field.
 */
export function mapDbOperationRowToDomain(row: unknown): VaultOperationRow {
  if (!isPlainObject(row)) {
    throw new VaultOpLogMapperError('operation row must be a plain object');
  }

  const opId = expectString(row, 'op_id');
  const opHash = expectString(row, 'op_hash');
  const vaultId = expectString(row, 'vault_id');
  const authorDeviceId = expectString(row, 'author_device_id');
  const opType = expectOperationType(row, 'op_type');
  const recordId = expectString(row, 'record_id');
  const recordType = expectRecordType(row, 'record_type');
  const baseRecordVersion = expectNullableNumber(row, 'base_record_version');
  const previousCiphertextHash = expectNullableString(row, 'previous_ciphertext_hash');
  const newRecordHash = expectNullableString(row, 'new_record_hash');
  const baseVaultHead = expectNullableString(row, 'base_vault_head');
  const resultingVaultHead = expectString(row, 'resulting_vault_head');
  const intentId = expectNullableString(row, 'intent_id');
  const rebasedFromOpId = expectNullableString(row, 'rebased_from_op_id');
  const payloadCiphertextHash = expectNullableString(row, 'payload_ciphertext_hash');
  const payloadAadHash = expectNullableString(row, 'payload_aad_hash');
  const signedBody = row.signed_body;
  const signature = expectString(row, 'signature');
  const signatureSchema = expectString(row, 'signature_schema');
  const trustEpoch = expectFiniteNumber(row, 'trust_epoch');
  const createdAtClient = expectString(row, 'created_at_client');
  const receivedAtServer = expectString(row, 'received_at_server');
  const sequenceNumber = expectFiniteNumber(row, 'sequence_number');

  if (signedBody === undefined || signedBody === null) {
    throw new VaultOpLogMapperError('missing signed_body');
  }

  return {
    opId,
    opHash,
    vaultId,
    authorDeviceId,
    opType,
    recordId,
    recordType,
    baseRecordVersion,
    previousCiphertextHash,
    newRecordHash,
    baseVaultHead,
    resultingVaultHead,
    intentId,
    rebasedFromOpId,
    payloadCiphertextHash,
    payloadAadHash,
    signedBody,
    signature,
    signatureSchema,
    trustEpoch,
    createdAtClient,
    receivedAtServer,
    sequenceNumber,
  };
}

/**
 * Map a raw DB record row to the domain type.
 */
export function mapDbRecordRowToDomain(row: unknown): VaultRecordRow {
  if (!isPlainObject(row)) {
    throw new VaultOpLogMapperError('record row must be a plain object');
  }

  return {
    vaultId: expectString(row, 'vault_id'),
    recordId: expectString(row, 'record_id'),
    recordType: expectRecordType(row, 'record_type'),
    recordVersion: expectFiniteNumber(row, 'record_version'),
    keyVersion: expectFiniteNumber(row, 'key_version'),
    aadHash: expectString(row, 'aad_hash'),
    ciphertextHash: expectString(row, 'ciphertext_hash'),
    nonce: expectString(row, 'nonce'),
    ciphertext: expectString(row, 'ciphertext'),
    lastOpId: expectString(row, 'last_op_id'),
    lastOpHash: expectString(row, 'last_op_hash'),
    isTombstone: expectBoolean(row, 'is_tombstone'),
    createdAt: expectString(row, 'created_at'),
    updatedAt: expectString(row, 'updated_at'),
  };
}

/**
 * Map a raw DB head row to the domain type.
 */
export function mapDbHeadRowToDomain(row: unknown): VaultHeadRow {
  if (!isPlainObject(row)) {
    throw new VaultOpLogMapperError('head row must be a plain object');
  }

  return {
    vaultId: expectString(row, 'vault_id'),
    currentHead: expectString(row, 'current_head'),
    currentOpId: expectNullableString(row, 'current_op_id'),
    currentSequenceNumber: expectFiniteNumber(row, 'current_sequence_number'),
    updatedAt: expectString(row, 'updated_at'),
  };
}

// ---------------------------------------------------------------------------
// Domain -> RPC request
// ---------------------------------------------------------------------------

/**
 * Build the RPC request for `submit_vault_operation` from domain inputs.
 */
export function buildSubmitVaultOperationRequest(
  operation: VaultOperationRow,
  recordPayload: {
    readonly aadHash: string;
    readonly ciphertextHash: string;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly keyVersion: number;
  } | null,
  deviceTrustPayload: unknown | null,
): RpcSubmitVaultOperationRequest {
  return {
    p_op: {
      op_id: operation.opId,
      op_hash: operation.opHash,
      vault_id: operation.vaultId,
      author_device_id: operation.authorDeviceId,
      op_type: operation.opType,
      record_id: operation.recordId,
      record_type: operation.recordType,
      base_record_version: operation.baseRecordVersion,
      previous_ciphertext_hash: operation.previousCiphertextHash,
      new_record_hash: operation.newRecordHash,
      base_vault_head: operation.baseVaultHead,
      resulting_vault_head: operation.resultingVaultHead,
      intent_id: operation.intentId,
      rebased_from_op_id: operation.rebasedFromOpId,
      payload_ciphertext_hash: operation.payloadCiphertextHash,
      payload_aad_hash: operation.payloadAadHash,
      signed_body: operation.signedBody,
      signature: operation.signature,
      signature_schema: operation.signatureSchema,
      trust_epoch: operation.trustEpoch,
      created_at_client: operation.createdAtClient,
    },
    p_record_payload: recordPayload
      ? {
          aad_hash: recordPayload.aadHash,
          ciphertext_hash: recordPayload.ciphertextHash,
          nonce: recordPayload.nonce,
          ciphertext: recordPayload.ciphertext,
          key_version: recordPayload.keyVersion,
        }
      : null,
    p_device_trust_payload: deviceTrustPayload,
  };
}

export function buildGetVaultHeadRequest(vaultId: string): RpcGetVaultHeadRequest {
  return { p_vault_id: vaultId };
}

export function buildGetVaultChangesSinceRequest(
  vaultId: string,
  sinceSequence: number,
  limit: number,
): RpcGetVaultChangesSinceRequest {
  return { p_vault_id: vaultId, p_since_sequence: sinceSequence, p_limit: limit };
}

export function buildGetVaultRecordsByIdsRequest(
  vaultId: string,
  recordIds: readonly string[],
): RpcGetVaultRecordsByIdsRequest {
  return { p_vault_id: vaultId, p_record_ids: [...recordIds] };
}

export function buildBootstrapVaultTrustRequest(
  vaultId: string,
  deviceId: string,
  publicSigningKey: string,
  deviceNameEncrypted: string,
  initialHead: string,
  initialOpId: string,
): RpcBootstrapVaultTrustRequest {
  return {
    p_vault_id: vaultId,
    p_device_id: deviceId,
    p_public_signing_key: publicSigningKey,
    p_device_name_encrypted: deviceNameEncrypted,
    p_initial_head: initialHead,
    p_initial_op_id: initialOpId,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function expectString(obj: Record<string, unknown>, key: string, context?: string): string {
  const value = obj[key];
  if (typeof value !== 'string') {
    const ctx = context ? ` (${context})` : '';
    throw new VaultOpLogMapperError(`expected string for ${key}${ctx}, got ${typeof value}`);
  }
  return value;
}

export function expectNullableString(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new VaultOpLogMapperError(`expected string | null for ${key}, got ${typeof value}`);
  }
  return value;
}

export function expectFiniteNumber(obj: Record<string, unknown>, key: string, context?: string): number {
  const value = obj[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    const ctx = context ? ` (${context})` : '';
    throw new VaultOpLogMapperError(`expected finite number for ${key}${ctx}, got ${typeof value}`);
  }
  return value;
}

function expectNullableNumber(obj: Record<string, unknown>, key: string): number | null {
  const value = obj[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new VaultOpLogMapperError(`expected finite number | null for ${key}, got ${typeof value}`);
  }
  return value;
}

function expectBoolean(obj: Record<string, unknown>, key: string): boolean {
  const value = obj[key];
  if (typeof value !== 'boolean') {
    throw new VaultOpLogMapperError(`expected boolean for ${key}, got ${typeof value}`);
  }
  return value;
}

function expectOperationType(obj: Record<string, unknown>, key: string): OperationType {
  const value = obj[key];
  if (!isOperationType(value)) {
    throw new VaultOpLogMapperError(`expected valid op_type for ${key}, got ${String(value)}`);
  }
  return value;
}

function expectRecordType(obj: Record<string, unknown>, key: string): RecordType {
  const value = obj[key];
  if (!isRecordType(value)) {
    throw new VaultOpLogMapperError(`expected valid record_type for ${key}, got ${String(value)}`);
  }
  return value;
}
