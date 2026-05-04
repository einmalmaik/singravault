// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * RPC-facing types for the vault operation log repository layer (Phase 3).
 *
 * This module defines:
 * - Raw DB row shapes (snake_case) returned by Supabase RPCs.
 * - RPC request shapes (snake_case) sent to Supabase RPCs.
 * - Discriminated result unions for every repository operation.
 *
 * No business logic lives here. These are pure wire shapes.
 */

import type { OperationType, RecordType } from './types';

// ---------------------------------------------------------------------------
// DB row shapes (exactly what Supabase returns from RPC table results)
// ---------------------------------------------------------------------------

/**
 * Raw operation row as returned by `get_vault_changes_since`.
 * All fields are required on the wire except the nullable ones.
 */
export interface DbVaultOperationRow {
  readonly op_id: string;
  readonly op_hash: string;
  readonly vault_id: string;
  readonly author_device_id: string;
  readonly op_type: string;
  readonly record_id: string;
  readonly record_type: string;
  readonly base_record_version: number | null;
  readonly previous_ciphertext_hash: string | null;
  readonly new_record_hash: string | null;
  readonly base_vault_head: string | null;
  readonly resulting_vault_head: string;
  readonly intent_id: string | null;
  readonly rebased_from_op_id: string | null;
  readonly payload_ciphertext_hash: string | null;
  readonly payload_aad_hash: string | null;
  readonly signed_body: unknown;
  readonly signature: string;
  readonly signature_schema: string;
  readonly trust_epoch: number;
  readonly created_at_client: string;
  readonly received_at_server: string;
  readonly sequence_number: number;
}

/**
 * Raw record row as returned by `get_vault_records_by_ids`.
 */
export interface DbVaultRecordRow {
  readonly vault_id: string;
  readonly record_id: string;
  readonly record_type: string;
  readonly record_version: number;
  readonly key_version: number;
  readonly aad_hash: string;
  readonly ciphertext_hash: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly last_op_id: string;
  readonly last_op_hash: string;
  readonly is_tombstone: boolean;
  readonly created_at: string;
  readonly updated_at: string;
}

/**
 * Raw head row as returned by `get_vault_head`.
 */
export interface DbVaultHeadRow {
  readonly vault_id: string;
  readonly current_head: string;
  readonly current_op_id: string | null;
  readonly current_sequence_number: number;
  readonly updated_at: string;
}

// ---------------------------------------------------------------------------
// Domain row shapes (camelCase, typed) produced by the mapper layer
// ---------------------------------------------------------------------------

/**
 * A vault operation after DB -> domain mapping.  The `signedBody`
 * field is the raw JSONB value from the server.  Callers must
 * canonicalise and verify it themselves; the repository does not
 * treat it as trusted.
 */
export interface VaultOperationRow {
  readonly opId: string;
  readonly opHash: string;
  readonly vaultId: string;
  readonly authorDeviceId: string;
  readonly opType: OperationType;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly baseRecordVersion: number | null;
  readonly previousCiphertextHash: string | null;
  readonly newRecordHash: string | null;
  readonly baseVaultHead: string | null;
  readonly resultingVaultHead: string;
  readonly intentId: string | null;
  readonly rebasedFromOpId: string | null;
  readonly payloadCiphertextHash: string | null;
  readonly payloadAadHash: string | null;
  readonly signedBody: unknown;
  readonly signature: string;
  readonly signatureSchema: string;
  readonly trustEpoch: number;
  readonly createdAtClient: string;
  readonly receivedAtServer: string;
  readonly sequenceNumber: number;
}

export interface VaultRecordRow {
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly aadHash: string;
  readonly ciphertextHash: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly lastOpId: string;
  readonly lastOpHash: string;
  readonly isTombstone: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultHeadRow {
  readonly vaultId: string;
  readonly currentHead: string;
  readonly currentOpId: string | null;
  readonly currentSequenceNumber: number;
  readonly updatedAt: string;
}

// ---------------------------------------------------------------------------
// RPC request shapes (snake_case, exactly what the RPC expects)
// ---------------------------------------------------------------------------

export interface RpcSubmitVaultOperationRequest {
  readonly p_op: {
    readonly op_id: string;
    readonly op_hash: string;
    readonly vault_id: string;
    readonly author_device_id: string;
    readonly op_type: string;
    readonly record_id: string;
    readonly record_type: string;
    readonly base_record_version: number | null;
    readonly previous_ciphertext_hash: string | null;
    readonly new_record_hash: string | null;
    readonly base_vault_head: string | null;
    readonly resulting_vault_head: string;
    readonly intent_id: string | null;
    readonly rebased_from_op_id: string | null;
    readonly payload_ciphertext_hash: string | null;
    readonly payload_aad_hash: string | null;
    readonly signed_body: unknown;
    readonly signature: string;
    readonly signature_schema: string;
    readonly trust_epoch: number;
    readonly created_at_client: string;
  };
  readonly p_record_payload: {
    readonly aad_hash: string;
    readonly ciphertext_hash: string;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly key_version: number;
  } | null;
  readonly p_device_trust_payload: unknown | null;
}

export interface RpcGetVaultHeadRequest {
  readonly p_vault_id: string;
}

export interface RpcGetVaultChangesSinceRequest {
  readonly p_vault_id: string;
  readonly p_since_sequence: number;
  readonly p_limit: number;
}

export interface RpcGetVaultRecordsByIdsRequest {
  readonly p_vault_id: string;
  readonly p_record_ids: string[];
}

export interface RpcBootstrapVaultTrustRequest {
  readonly p_vault_id: string;
  readonly p_device_id: string;
  readonly p_public_signing_key: string;
  readonly p_device_name_encrypted: string;
  readonly p_initial_head: string;
  readonly p_initial_op_id: string;
}

// ---------------------------------------------------------------------------
// Result unions for repository operations
// ---------------------------------------------------------------------------

export type SubmitVaultOperationResult =
  | { readonly kind: 'applied'; readonly idempotent: boolean; readonly opId: string; readonly sequenceNumber: number; readonly resultingVaultHead: string; readonly currentHead: string; readonly currentSequenceNumber: number }
  | { readonly kind: 'rebaseNeeded'; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordConflictStaleVersion'; readonly currentRecordVersion: number; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordConflictStaleCiphertextHash'; readonly currentRecordVersion: number; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordNotFound'; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordTypeMismatch'; readonly currentRecordVersion: number; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordAlreadyExists'; readonly currentRecordVersion: number; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'createMustNotCarryBase' }
  | { readonly kind: 'duplicateOpIdDifferentHash' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'vaultOwnershipError' }
  | { readonly kind: 'rpcError'; readonly code: string; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };

export type GetVaultHeadResult =
  | { readonly kind: 'success'; readonly head: VaultHeadRow }
  | { readonly kind: 'notFound' }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'vaultOwnershipError' }
  | { readonly kind: 'rpcError'; readonly code: string; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };

export type GetVaultChangesSinceResult =
  | { readonly kind: 'success'; readonly operations: readonly VaultOperationRow[] }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'vaultOwnershipError' }
  | { readonly kind: 'rpcError'; readonly code: string; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };

export type GetVaultRecordsByIdsResult =
  | { readonly kind: 'success'; readonly records: readonly VaultRecordRow[] }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'vaultOwnershipError' }
  | { readonly kind: 'rpcError'; readonly code: string; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };

export type BootstrapVaultTrustResult =
  | { readonly kind: 'bootstrapped'; readonly vaultId: string; readonly deviceId: string; readonly initialHead: string; readonly initialOpId: string }
  | { readonly kind: 'trustListAlreadyExists'; readonly existingCount: number }
  | { readonly kind: 'headAlreadyExists'; readonly currentHead: string }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'vaultOwnershipError' }
  | { readonly kind: 'rpcError'; readonly code: string; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };
