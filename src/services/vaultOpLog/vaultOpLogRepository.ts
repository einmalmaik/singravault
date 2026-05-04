// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Repository layer for vault operation log RPCs (Phase 3).
 *
 * Wraps the five SECURITY DEFINER RPCs defined in Phase 2:
 *   - submit_vault_operation
 *   - get_vault_head
 *   - get_vault_changes_since
 *   - get_vault_records_by_ids
 *   - bootstrap_vault_trust
 *
 * Responsibilities:
 * - Call only the allowed RPCs.
 * - Never issue direct INSERT / UPDATE / UPSERT / DELETE on vault tables.
 * - Map raw Supabase results to typed domain results.
 * - Classify RPC errors and malformed responses into discriminated unions.
 * - Never log secrets, ciphertexts, signatures or plaintexts.
 *
 * Non-responsibilities (Phase 5):
 * - Verifying signatures or hashes.
 * - Deciding whether a record is trustworthy.
 * - State-machine transitions.
 */

import {
  mapDbHeadRowToDomain,
  mapDbOperationRowToDomain,
  mapDbRecordRowToDomain,
  buildSubmitVaultOperationRequest,
  buildGetVaultHeadRequest,
  buildGetVaultChangesSinceRequest,
  buildGetVaultRecordsByIdsRequest,
  buildBootstrapVaultTrustRequest,
  VaultOpLogMapperError,
  isPlainObject,
  expectString,
  expectNullableString,
  expectFiniteNumber,
} from './vaultOpLogMappers';
import type {
  BootstrapVaultTrustResult,
  DbVaultHeadRow,
  DbVaultOperationRow,
  DbVaultRecordRow,
  GetVaultChangesSinceResult,
  GetVaultHeadResult,
  GetVaultRecordsByIdsResult,
  SubmitVaultOperationResult,
  VaultOperationRow,
} from './vaultOpLogRpcTypes';

// ---------------------------------------------------------------------------
// Minimal Supabase client interface (kept small so tests can mock easily)
// ---------------------------------------------------------------------------

export interface SupabaseRpcClient {
  rpc<T = unknown>(
    fn: string,
    params: Record<string, unknown>,
    options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): Promise<{
    data: T | null;
    error: { code: string; message: string; details?: string; hint?: string } | null;
  }>;
}

// ---------------------------------------------------------------------------
// Error classification helpers
// ---------------------------------------------------------------------------

function classifySubmitRpcError(
  error: { code: string; message: string },
): SubmitVaultOperationResult {
  const msg = error.message;
  if (msg.includes('Not authenticated')) {
    return { kind: 'unauthorized' };
  }
  if (msg.includes('Vault does not belong to caller')) {
    return { kind: 'vaultOwnershipError' };
  }
  if (msg.includes('op_id reused with a different op_hash')) {
    return { kind: 'duplicateOpIdDifferentHash' };
  }
  return { kind: 'rpcError', code: error.code, message: msg };
}

type ReadRpcErrorResult =
  | { kind: 'unauthorized' }
  | { kind: 'vaultOwnershipError' }
  | { kind: 'rpcError'; code: string; message: string };

function classifyReadRpcError(
  error: { code: string; message: string },
): ReadRpcErrorResult {
  const msg = error.message;
  if (msg.includes('Not authenticated')) {
    return { kind: 'unauthorized' };
  }
  if (msg.includes('Vault does not belong to caller')) {
    return { kind: 'vaultOwnershipError' };
  }
  return { kind: 'rpcError', code: error.code, message: msg };
}

function classifyBootstrapRpcError(
  error: { code: string; message: string },
): BootstrapVaultTrustResult {
  const msg = error.message;
  if (msg.includes('Not authenticated')) {
    return { kind: 'unauthorized' };
  }
  if (msg.includes('Vault does not belong to caller')) {
    return { kind: 'vaultOwnershipError' };
  }
  return { kind: 'rpcError', code: error.code, message: msg };
}

// ---------------------------------------------------------------------------
// submit_vault_operation
// ---------------------------------------------------------------------------

/**
 * Submit a signed vault operation via `submit_vault_operation`.
 *
 * The repository does not verify the signature.  It only transports the
 * operation and classifies the RPC response.
 */
export async function submitVaultOperation(
  client: SupabaseRpcClient,
  operation: VaultOperationRow,
  recordPayload: {
    readonly aadHash: string;
    readonly ciphertextHash: string;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly keyVersion: number;
  } | null,
  deviceTrustPayload: unknown | null,
): Promise<SubmitVaultOperationResult> {
  const request = buildSubmitVaultOperationRequest(operation, recordPayload, deviceTrustPayload);

  const { data, error } = await client.rpc<Record<string, unknown>>('submit_vault_operation', request as unknown as Record<string, unknown>);

  if (error) {
    return classifySubmitRpcError(error);
  }

  if (data === null || !isPlainObject(data)) {
    return { kind: 'malformedResponse', reason: 'submit_vault_operation returned null or non-object' };
  }

  const applied = data.applied;
  if (typeof applied !== 'boolean') {
    return { kind: 'malformedResponse', reason: 'missing or non-boolean applied field' };
  }

  if (applied === true) {
    const idempotent = data.idempotent === true;
    const opId = expectString(data, 'op_id', 'applied true');
    const sequenceNumber = expectFiniteNumber(data, 'sequence_number', 'applied true');
    const resultingVaultHead = expectString(data, 'resulting_vault_head', 'applied true');
    const currentHead = expectString(data, 'current_head', 'applied true');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'applied true');
    return {
      kind: 'applied',
      idempotent,
      opId,
      sequenceNumber,
      resultingVaultHead,
      currentHead,
      currentSequenceNumber,
    };
  }

  // applied === false → conflict
  const conflictReason = expectNullableString(data, 'conflict_reason');

  if (conflictReason === 'stale_vault_head') {
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'stale_vault_head');
    return { kind: 'rebaseNeeded', currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'stale_record_version') {
    const currentRecordVersion = expectFiniteNumber(data, 'current_record_version', 'stale_record_version');
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'stale_record_version');
    return { kind: 'recordConflictStaleVersion', currentRecordVersion, currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'stale_previous_ciphertext_hash') {
    const currentRecordVersion = expectFiniteNumber(data, 'current_record_version', 'stale_previous_ciphertext_hash');
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'stale_previous_ciphertext_hash');
    return { kind: 'recordConflictStaleCiphertextHash', currentRecordVersion, currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'record_not_found') {
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'record_not_found');
    return { kind: 'recordNotFound', currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'record_type_mismatch') {
    const currentRecordVersion = expectFiniteNumber(data, 'current_record_version', 'record_type_mismatch');
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'record_type_mismatch');
    return { kind: 'recordTypeMismatch', currentRecordVersion, currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'record_already_exists') {
    const currentRecordVersion = expectFiniteNumber(data, 'current_record_version', 'record_already_exists');
    const currentHead = expectNullableString(data, 'current_head');
    const currentSequenceNumber = expectFiniteNumber(data, 'current_sequence_number', 'record_already_exists');
    return { kind: 'recordAlreadyExists', currentRecordVersion, currentHead, currentSequenceNumber };
  }

  if (conflictReason === 'create_must_not_carry_base') {
    return { kind: 'createMustNotCarryBase' };
  }

  return {
    kind: 'malformedResponse',
    reason: `unrecognized conflict_reason: ${String(conflictReason)}`,
  };
}

// ---------------------------------------------------------------------------
// get_vault_head
// ---------------------------------------------------------------------------

export async function getVaultHead(
  client: SupabaseRpcClient,
  vaultId: string,
): Promise<GetVaultHeadResult> {
  const request = buildGetVaultHeadRequest(vaultId);
  const { data, error } = await client.rpc<DbVaultHeadRow[]>('get_vault_head', request as unknown as Record<string, unknown>);

  if (error) {
    return classifyReadRpcError(error) as GetVaultHeadResult;
  }

  if (!Array.isArray(data)) {
    return { kind: 'malformedResponse', reason: 'get_vault_head returned non-array' };
  }

  if (data.length === 0) {
    return { kind: 'notFound' };
  }

  try {
    const head = mapDbHeadRowToDomain(data[0]);
    return { kind: 'success', head };
  } catch (e) {
    const reason = e instanceof VaultOpLogMapperError ? e.message : 'unknown mapper error';
    return { kind: 'malformedResponse', reason };
  }
}

// ---------------------------------------------------------------------------
// get_vault_changes_since
// ---------------------------------------------------------------------------

export async function getVaultChangesSince(
  client: SupabaseRpcClient,
  vaultId: string,
  sinceSequence: number,
  limit: number,
): Promise<GetVaultChangesSinceResult> {
  const request = buildGetVaultChangesSinceRequest(vaultId, sinceSequence, limit);
  const { data, error } = await client.rpc<DbVaultOperationRow[]>('get_vault_changes_since', request as unknown as Record<string, unknown>);

  if (error) {
    return classifyReadRpcError(error) as GetVaultChangesSinceResult;
  }

  if (!Array.isArray(data)) {
    return { kind: 'malformedResponse', reason: 'get_vault_changes_since returned non-array' };
  }

  const operations: VaultOperationRow[] = [];
  for (let index = 0; index < data.length; index += 1) {
    try {
      operations.push(mapDbOperationRowToDomain(data[index]));
    } catch (e) {
      const reason = e instanceof VaultOpLogMapperError ? e.message : 'unknown mapper error';
      return { kind: 'malformedResponse', reason: `row ${index}: ${reason}` };
    }
  }

  return { kind: 'success', operations };
}

// ---------------------------------------------------------------------------
// get_vault_records_by_ids
// ---------------------------------------------------------------------------

export async function getVaultRecordsByIds(
  client: SupabaseRpcClient,
  vaultId: string,
  recordIds: readonly string[],
): Promise<GetVaultRecordsByIdsResult> {
  const request = buildGetVaultRecordsByIdsRequest(vaultId, recordIds);
  const { data, error } = await client.rpc<DbVaultRecordRow[]>('get_vault_records_by_ids', request as unknown as Record<string, unknown>);

  if (error) {
    return classifyReadRpcError(error) as GetVaultRecordsByIdsResult;
  }

  if (!Array.isArray(data)) {
    return { kind: 'malformedResponse', reason: 'get_vault_records_by_ids returned non-array' };
  }

  const records = [];
  for (let index = 0; index < data.length; index += 1) {
    try {
      records.push(mapDbRecordRowToDomain(data[index]));
    } catch (e) {
      const reason = e instanceof VaultOpLogMapperError ? e.message : 'unknown mapper error';
      return { kind: 'malformedResponse', reason: `row ${index}: ${reason}` };
    }
  }

  return { kind: 'success', records };
}

// ---------------------------------------------------------------------------
// bootstrap_vault_trust
// ---------------------------------------------------------------------------

export async function bootstrapVaultTrust(
  client: SupabaseRpcClient,
  vaultId: string,
  deviceId: string,
  publicSigningKey: string,
  deviceNameEncrypted: string,
  initialHead: string,
  initialOpId: string,
): Promise<BootstrapVaultTrustResult> {
  const request = buildBootstrapVaultTrustRequest(
    vaultId,
    deviceId,
    publicSigningKey,
    deviceNameEncrypted,
    initialHead,
    initialOpId,
  );
  const { data, error } = await client.rpc<Record<string, unknown>>('bootstrap_vault_trust', request as unknown as Record<string, unknown>);

  if (error) {
    return classifyBootstrapRpcError(error);
  }

  if (data === null || !isPlainObject(data)) {
    return { kind: 'malformedResponse', reason: 'bootstrap_vault_trust returned null or non-object' };
  }

  const bootstrapped = data.bootstrapped;
  if (typeof bootstrapped !== 'boolean') {
    return { kind: 'malformedResponse', reason: 'missing or non-boolean bootstrapped field' };
  }

  if (bootstrapped === true) {
    return {
      kind: 'bootstrapped',
      vaultId: expectString(data, 'vault_id', 'bootstrapped true'),
      deviceId: expectString(data, 'device_id', 'bootstrapped true'),
      initialHead: expectString(data, 'initial_head', 'bootstrapped true'),
      initialOpId: expectString(data, 'initial_op_id', 'bootstrapped true'),
    };
  }

  const reason = expectNullableString(data, 'reason');

  if (reason === 'trust_list_already_exists') {
    const existingCount = expectFiniteNumber(data, 'existing_count', 'trust_list_already_exists');
    return { kind: 'trustListAlreadyExists', existingCount };
  }

  if (reason === 'head_already_exists') {
    const currentHead = expectString(data, 'current_head', 'head_already_exists');
    return { kind: 'headAlreadyExists', currentHead };
  }

  return {
    kind: 'malformedResponse',
    reason: `unrecognized bootstrap reason: ${String(reason)}`,
  };
}

