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
  ApprovePendingDeviceRequestResult,
  CreatePendingDeviceRequestResult,
  DbPendingDeviceRequestRow,
  GetPendingDeviceRequestsResult,
  RejectPendingDeviceRequestResult,
} from './vaultOpLogRpcTypes';
import type { PendingDeviceRequestRow } from './addDeviceFlowTypes';

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

  return { kind: 'malformedResponse', reason: `unrecognized reason: ${String(reason)}` };
}

// ---------------------------------------------------------------------------
// Add-Device-Flow: Pending Device Request Repository
// ---------------------------------------------------------------------------

/**
 * Build request for create_pending_device_request RPC.
 */
function buildCreatePendingDeviceRequestRequest(input: {
  readonly vaultId: string;
  readonly requestedDeviceId: string;
  readonly requestedDeviceName: string;
  readonly requestedPublicSigningKey: string;
  readonly requestedDevicePlatform: string | null;
  readonly pairingNonce: string;
}): Record<string, unknown> {
  return {
    p_vault_id: input.vaultId,
    p_requested_device_id: input.requestedDeviceId,
    p_requested_device_name: input.requestedDeviceName,
    p_requested_public_signing_key: input.requestedPublicSigningKey,
    p_requested_device_platform: input.requestedDevicePlatform,
    p_pairing_nonce: input.pairingNonce,
  };
}

/**
 * Map raw DB row to domain PendingDeviceRequestRow.
 */
function mapDbPendingDeviceRequestRow(raw: DbPendingDeviceRequestRow): PendingDeviceRequestRow {
  return {
    requestId: raw.request_id,
    requestedDeviceId: raw.requested_device_id,
    requestedDeviceName: raw.requested_device_name,
    requestedPublicSigningKey: raw.requested_public_signing_key,
    requestedDevicePlatform: (raw.requested_device_platform ?? 'unknown') as PendingDeviceRequestRow['requestedDevicePlatform'],
    pairingNonce: raw.pairing_nonce,
    challengeCreatedAt: raw.challenge_created_at,
    challengeExpiresAt: raw.challenge_expires_at,
    status: raw.status as PendingDeviceRequestRow['status'],
    createdAt: raw.created_at,
  };
}

/**
 * Create a pending device request from the browser.
 *
 * SECURITY: This does NOT make the device trusted. It only stores
 * a temporary pairing request. Trust is established only after
 * a cryptographically verified signed add_device operation.
 */
export async function createPendingDeviceRequest(
  client: SupabaseRpcClient,
  input: {
    readonly vaultId: string;
    readonly requestedDeviceId: string;
    readonly requestedDeviceName: string;
    readonly requestedPublicSigningKey: string;
    readonly requestedDevicePlatform: string | null;
    readonly pairingNonce: string;
  },
): Promise<CreatePendingDeviceRequestResult> {
  const request = buildCreatePendingDeviceRequestRequest(input);

  const { data, error } = await client.rpc<Record<string, unknown>>(
    'create_pending_device_request',
    request as unknown as Record<string, unknown>,
  );

  if (error) {
    const msg = error.message;
    if (msg.includes('Not authenticated')) {
      return { kind: 'unauthorized' };
    }
    if (msg.includes('Vault does not belong to caller')) {
      return { kind: 'vaultOwnershipError' };
    }
    return { kind: 'rpcError', code: error.code, message: msg };
  }

  if (data === null || !isPlainObject(data)) {
    return { kind: 'malformedResponse', reason: 'create_pending_device_request returned null or non-object' };
  }

  const created = data.created;
  if (typeof created !== 'boolean') {
    return { kind: 'malformedResponse', reason: 'missing or non-boolean created field' };
  }

  if (created === true) {
    const requestId = expectString(data, 'request_id', 'created true');
    const expiresAt = expectString(data, 'expires_at', 'created true');
    return { kind: 'created', requestId, expiresAt };
  }

  const reason = expectNullableString(data, 'reason');
  if (reason === 'device_already_trusted') {
    return { kind: 'alreadyTrusted', reason: 'device_already_trusted' };
  }

  return { kind: 'malformedResponse', reason: `unrecognized reason: ${String(reason)}` };
}

/**
 * Get pending device requests for a vault.
 *
 * SECURITY: Only returns requests owned by the authenticated user.
 * Expired requests are filtered out server-side.
 */
export async function getPendingDeviceRequests(
  client: SupabaseRpcClient,
  vaultId: string,
): Promise<GetPendingDeviceRequestsResult> {
  const request = { p_vault_id: vaultId };

  const { data, error } = await client.rpc<DbPendingDeviceRequestRow[]>(
    'get_pending_device_requests',
    request as unknown as Record<string, unknown>,
  );

  if (error) {
    const msg = error.message;
    if (msg.includes('Not authenticated')) {
      return { kind: 'unauthorized' };
    }
    if (msg.includes('Vault does not belong to caller')) {
      return { kind: 'vaultOwnershipError' };
    }
    return { kind: 'rpcError', code: error.code, message: msg };
  }

  if (!Array.isArray(data)) {
    return { kind: 'malformedResponse', reason: 'get_pending_device_requests returned non-array' };
  }

  const requests: PendingDeviceRequestRow[] = [];
  for (let index = 0; index < data.length; index += 1) {
    try {
      requests.push(mapDbPendingDeviceRequestRow(data[index]));
    } catch (e) {
      const reason = e instanceof VaultOpLogMapperError ? e.message : 'unknown mapper error';
      return { kind: 'malformedResponse', reason: `row ${index}: ${reason}` };
    }
  }

  return { kind: 'success', requests };
}

/**
 * Approve a pending device request.
 *
 * SECURITY: This does NOT create trust by itself. It validates that a
 * trusted device may approve this request and returns the device data.
 * The caller MUST:
 * 1. Build a canonical add_device operation with the returned device data
 * 2. Sign it with the existing trusted device's private signing key
 * 3. Submit the signed operation via submitVaultOperation()
 *
 * Trust is only established after the signed operation is verified.
 */
export async function approvePendingDeviceRequest(
  client: SupabaseRpcClient,
  requestId: string,
  approverDeviceId: string,
): Promise<ApprovePendingDeviceRequestResult> {
  const request = {
    p_request_id: requestId,
    p_approver_device_id: approverDeviceId,
  };

  const { data, error } = await client.rpc<Record<string, unknown>>(
    'approve_pending_device_request',
    request as unknown as Record<string, unknown>,
  );

  if (error) {
    const msg = error.message;
    if (msg.includes('Not authenticated')) {
      return { kind: 'unauthorized' };
    }
    if (msg.includes('Vault does not belong to caller')) {
      return { kind: 'vaultOwnershipError' };
    }
    return { kind: 'rpcError', code: error.code, message: msg };
  }

  if (data === null || !isPlainObject(data)) {
    return { kind: 'malformedResponse', reason: 'approve_pending_device_request returned null or non-object' };
  }

  const approved = data.approved;
  if (typeof approved !== 'boolean') {
    return { kind: 'malformedResponse', reason: 'missing or non-boolean approved field' };
  }

  if (approved === true) {
    return {
      kind: 'approved',
      requestId: expectString(data, 'request_id', 'approved true'),
      requestedDeviceId: expectString(data, 'requested_device_id', 'approved true'),
      requestedPublicSigningKey: expectString(data, 'requested_public_signing_key', 'approved true'),
      requestedDeviceName: expectString(data, 'requested_device_name', 'approved true'),
      vaultId: expectString(data, 'vault_id','approved true'),
    };
  }

  const reason = expectNullableString(data, 'reason');
  if (reason === 'request_not_found') {
    return { kind: 'requestNotFound' };
  }
  if (reason === 'request_expired') {
    return { kind: 'requestExpired' };
  }
  if (reason === 'approver_not_trusted') {
    return { kind: 'approverNotTrusted' };
  }

  return { kind: 'malformedResponse', reason: `unrecognized reason: ${String(reason)}` };
}

/**
 * Reject a pending device request.
 *
 * SECURITY: This simply marks the request as rejected.
 * No trust is created.
 */
export async function rejectPendingDeviceRequest(
  client: SupabaseRpcClient,
  requestId: string,
  rejecterDeviceId: string,
): Promise<RejectPendingDeviceRequestResult> {
  const request = {
    p_request_id: requestId,
    p_rejecter_device_id: rejecterDeviceId,
  };

  const { data, error } = await client.rpc<Record<string, unknown>>(
    'reject_pending_device_request',
    request as unknown as Record<string, unknown>,
  );

  if (error) {
    const msg = error.message;
    if (msg.includes('Not authenticated')) {
      return { kind: 'unauthorized' };
    }
    if (msg.includes('Vault does not belong to caller')) {
      return { kind: 'vaultOwnershipError' };
    }
    return { kind: 'rpcError', code: error.code, message: msg };
  }

  if (data === null || !isPlainObject(data)) {
    return { kind: 'malformedResponse', reason: 'reject_pending_device_request returned null or non-object' };
  }

  const rejected = data.rejected;
  if (typeof rejected !== 'boolean') {
    return { kind: 'malformedResponse', reason: 'missing or non-boolean rejected field' };
  }

  if (rejected === true) {
    return {
      kind: 'rejected',
      requestId: expectString(data, 'request_id', 'rejected true'),
    };
  }

  const reason = expectNullableString(data, 'reason');
  if (reason === 'request_not_found') {
    return { kind: 'requestNotFound' };
  }

  return { kind: 'malformedResponse', reason: `unrecognized reason: ${String(reason)}` };
}
