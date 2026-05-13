// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import type {
  BuiltCollectionOperation,
} from './operationBuilder';
import {
  isCollectionOperationType,
  isCollectionRecordType,
  type CollectionHeadRow,
  type CollectionKeyEnvelopeRow,
  type CollectionOperationRow,
  type CollectionRecordRow,
  type CollectionTrustedAuthorDevice,
} from './types';

export type SubmitCollectionOperationResult =
  | { readonly kind: 'applied'; readonly idempotent: boolean; readonly opId: string; readonly sequenceNumber: number; readonly resultingCollectionHead: string; readonly currentHead: string; readonly currentSequenceNumber: number }
  | { readonly kind: 'rebaseNeeded'; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'recordConflict'; readonly reason: 'stale_record_version' | 'stale_previous_ciphertext_hash' | 'record_type_mismatch' | 'record_already_exists' | 'record_not_found' | 'create_must_not_carry_base' | 'collection_not_found'; readonly currentRecordVersion?: number; readonly currentHead: string | null; readonly currentSequenceNumber: number }
  | { readonly kind: 'unauthorized' }
  | { readonly kind: 'rpcError'; readonly message: string }
  | { readonly kind: 'malformedResponse'; readonly reason: string };

export async function submitCollectionOperation(
  client: SupabaseRpcClient,
  built: BuiltCollectionOperation,
): Promise<SubmitCollectionOperationResult> {
  const body = built.signedOperation.body;
  const { data, error } = await client.rpc<Record<string, unknown>>('submit_collection_operation', {
    p_op: {
      op_id: body.opId,
      op_hash: built.signedOperation.opHash,
      collection_id: body.collectionId,
      actor_user_id: body.actorUserId,
      actor_vault_id: body.actorVaultId,
      author_device_id: body.authorDeviceId,
      op_type: body.opType,
      record_id: body.recordId,
      record_type: body.recordType,
      base_record_version: body.baseRecordVersion,
      previous_ciphertext_hash: body.previousCiphertextHash,
      new_record_hash: body.newRecordHash,
      base_collection_head: body.baseCollectionHead,
      resulting_collection_head: built.resultingCollectionHead,
      payload_ciphertext_hash: body.payloadCiphertextHash,
      payload_aad_hash: body.payloadAadHash,
      signed_body: body,
      signature: built.signedOperation.signature,
      signature_schema: body.signatureSchema,
      trust_epoch: body.trustEpoch,
      created_at_client: body.createdAtClient,
      target_user_id: built.membership?.targetUserId ?? null,
      target_permission: built.membership?.targetPermission ?? null,
    },
    p_record_payload: {
      aad_hash: built.sealedRecord.aadHash,
      ciphertext_hash: built.sealedRecord.ciphertextHash,
      nonce: built.sealedRecord.nonceB64Url,
      ciphertext: built.sealedRecord.ciphertextB64Url,
      key_version: built.sealedRecord.aad.keyVersion,
    },
    p_key_envelope: built.keyEnvelope ? {
      recipient_user_id: built.keyEnvelope.recipientUserId,
      key_version: built.keyEnvelope.keyVersion,
      wrapped_key: built.keyEnvelope.wrappedKey,
      pq_wrapped_key: built.keyEnvelope.pqWrappedKey,
    } : null,
  });

  if (error) {
    if (error.message.includes('Not authenticated')) return { kind: 'unauthorized' };
    return { kind: 'rpcError', message: error.message };
  }
  if (!data || typeof data !== 'object') {
    return { kind: 'malformedResponse', reason: 'submit_collection_operation returned null or non-object' };
  }
  if (data.applied === true) {
    return {
      kind: 'applied',
      idempotent: data.idempotent === true,
      opId: expectString(data, 'op_id'),
      sequenceNumber: expectNumber(data, 'sequence_number'),
      resultingCollectionHead: expectString(data, 'resulting_collection_head'),
      currentHead: expectString(data, 'current_head'),
      currentSequenceNumber: expectNumber(data, 'current_sequence_number'),
    };
  }
  if (data.applied !== false) {
    return { kind: 'malformedResponse', reason: 'missing applied boolean' };
  }
  const reason = data.conflict_reason;
  if (reason === 'stale_collection_head') {
    return {
      kind: 'rebaseNeeded',
      currentHead: expectNullableString(data, 'current_head'),
      currentSequenceNumber: expectNumber(data, 'current_sequence_number'),
    };
  }
  if (
    reason === 'stale_record_version'
    || reason === 'stale_previous_ciphertext_hash'
    || reason === 'record_type_mismatch'
    || reason === 'record_already_exists'
    || reason === 'record_not_found'
    || reason === 'create_must_not_carry_base'
    || reason === 'collection_not_found'
  ) {
    return {
      kind: 'recordConflict',
      reason,
      currentRecordVersion: typeof data.current_record_version === 'number' ? data.current_record_version : undefined,
      currentHead: expectNullableString(data, 'current_head'),
      currentSequenceNumber: typeof data.current_sequence_number === 'number' ? data.current_sequence_number : 0,
    };
  }
  return { kind: 'malformedResponse', reason: `unrecognized conflict_reason: ${String(reason)}` };
}

export async function getCollectionHead(
  client: SupabaseRpcClient,
  collectionId: string,
): Promise<CollectionHeadRow | null> {
  const { data, error } = await client.rpc<unknown[]>('get_collection_head', { p_collection_id: collectionId });
  if (error) throw new Error(error.message);
  if (!Array.isArray(data) || data.length === 0) return null;
  const row = data[0] as Record<string, unknown>;
  return {
    collectionId: expectString(row, 'collection_id'),
    currentHead: expectNullableString(row, 'current_head'),
    currentOpId: expectNullableString(row, 'current_op_id'),
    currentSequenceNumber: expectNumber(row, 'current_sequence_number'),
    updatedAt: expectString(row, 'updated_at'),
  };
}

export async function getCollectionChangesSince(
  client: SupabaseRpcClient,
  collectionId: string,
  sinceSequence: number,
): Promise<CollectionOperationRow[]> {
  const { data, error } = await client.rpc<unknown[]>('get_collection_changes_since', {
    p_collection_id: collectionId,
    p_since_sequence: sinceSequence,
    p_limit: 1000,
  });
  if (error) throw new Error(error.message);
  if (!Array.isArray(data)) throw new Error('get_collection_changes_since returned non-array');
  return data.map(mapOperationRow);
}

export async function getCollectionRecordsByIds(
  client: SupabaseRpcClient,
  collectionId: string,
  recordIds: string[],
): Promise<CollectionRecordRow[]> {
  const { data, error } = await client.rpc<unknown[]>('get_collection_records_by_ids', {
    p_collection_id: collectionId,
    p_record_ids: recordIds,
  });
  if (error) throw new Error(error.message);
  if (!Array.isArray(data)) throw new Error('get_collection_records_by_ids returned non-array');
  return data.map(mapRecordRow);
}

export async function getCollectionAuthorTrustMaterial(
  client: SupabaseRpcClient,
  collectionId: string,
  authorUserIds: string[],
): Promise<CollectionTrustedAuthorDevice[]> {
  const { data, error } = await client.rpc<unknown[]>('get_collection_author_trust_material', {
    p_collection_id: collectionId,
    p_author_user_ids: authorUserIds,
  });
  if (error) throw new Error(error.message);
  if (!Array.isArray(data)) throw new Error('get_collection_author_trust_material returned non-array');
  return data.map((raw) => {
    const row = raw as Record<string, unknown>;
    const status = expectString(row, 'status');
    if (status !== 'trusted' && status !== 'revoked') {
      throw new Error('invalid trust status');
    }
    return {
      userId: expectString(row, 'user_id'),
      vaultId: expectString(row, 'vault_id'),
      deviceId: expectString(row, 'device_id'),
      publicSigningKey: expectString(row, 'public_signing_key'),
      trustEpoch: expectNumber(row, 'trust_epoch'),
      status,
    };
  });
}

export async function getCollectionKeyEnvelope(
  client: SupabaseRpcClient,
  collectionId: string,
): Promise<CollectionKeyEnvelopeRow | null> {
  const { data, error } = await client.rpc<unknown[]>('get_collection_key_envelope', { p_collection_id: collectionId });
  if (error) throw new Error(error.message);
  if (!Array.isArray(data) || data.length === 0) return null;
  const row = data[0] as Record<string, unknown>;
  return {
    collectionId: expectString(row, 'collection_id'),
    userId: expectString(row, 'user_id'),
    keyVersion: expectNumber(row, 'key_version'),
    wrappedKey: expectString(row, 'wrapped_key'),
    pqWrappedKey: expectString(row, 'pq_wrapped_key'),
    updatedAt: expectString(row, 'updated_at'),
  };
}

function mapOperationRow(raw: unknown): CollectionOperationRow {
  const row = raw as Record<string, unknown>;
  const opType = expectString(row, 'op_type');
  const recordType = expectString(row, 'record_type');
  if (!isCollectionOperationType(opType) || !isCollectionRecordType(recordType)) {
    throw new Error('invalid collection operation row type');
  }
  return {
    opId: expectString(row, 'op_id'),
    opHash: expectString(row, 'op_hash'),
    collectionId: expectString(row, 'collection_id'),
    actorUserId: expectString(row, 'actor_user_id'),
    actorVaultId: expectString(row, 'actor_vault_id'),
    authorDeviceId: expectString(row, 'author_device_id'),
    opType,
    recordId: expectString(row, 'record_id'),
    recordType,
    baseRecordVersion: expectNullableNumber(row, 'base_record_version'),
    previousCiphertextHash: expectNullableString(row, 'previous_ciphertext_hash'),
    newRecordHash: expectNullableString(row, 'new_record_hash'),
    baseCollectionHead: expectNullableString(row, 'base_collection_head'),
    resultingCollectionHead: expectString(row, 'resulting_collection_head'),
    payloadCiphertextHash: expectNullableString(row, 'payload_ciphertext_hash'),
    payloadAadHash: expectNullableString(row, 'payload_aad_hash'),
    signedBody: row.signed_body,
    signature: expectString(row, 'signature'),
    signatureSchema: expectString(row, 'signature_schema'),
    trustEpoch: expectNumber(row, 'trust_epoch'),
    createdAtClient: expectString(row, 'created_at_client'),
    receivedAtServer: expectString(row, 'received_at_server'),
    sequenceNumber: expectNumber(row, 'sequence_number'),
  };
}

function mapRecordRow(raw: unknown): CollectionRecordRow {
  const row = raw as Record<string, unknown>;
  const recordType = expectString(row, 'record_type');
  if (!isCollectionRecordType(recordType)) throw new Error('invalid collection record row type');
  return {
    collectionId: expectString(row, 'collection_id'),
    recordId: expectString(row, 'record_id'),
    recordType,
    recordVersion: expectNumber(row, 'record_version'),
    keyVersion: expectNumber(row, 'key_version'),
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

function expectString(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  if (typeof value !== 'string') throw new Error(`expected string for ${field}`);
  return value;
}

function expectNullableString(row: Record<string, unknown>, field: string): string | null {
  const value = row[field];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw new Error(`expected nullable string for ${field}`);
  return value;
}

function expectNumber(row: Record<string, unknown>, field: string): number {
  const value = row[field];
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`expected number for ${field}`);
  return value;
}

function expectNullableNumber(row: Record<string, unknown>, field: string): number | null {
  const value = row[field];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`expected nullable number for ${field}`);
  return value;
}

function expectBoolean(row: Record<string, unknown>, field: string): boolean {
  const value = row[field];
  if (typeof value !== 'boolean') throw new Error(`expected boolean for ${field}`);
  return value;
}
