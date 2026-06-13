// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { randomUuid } from '@msdis/shield/random';
import { canonicalizeVaultStructure } from '@/services/vaultOpLog/canonicalJson';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import { buildCollectionOperation } from './operationBuilder';
import {
  getCollectionAuthorTrustMaterial,
  getCollectionChangesSince,
  getCollectionHead,
  getCollectionRecordsByIds,
  submitCollectionOperation,
} from './repository';
import { buildVerifiedCollectionState, type LocalCollectionState } from './stateMachine';
import type { CollectionRecordType } from './types';

export class CollectionOpLogCrudServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CollectionOpLogCrudServiceError';
  }
}

export class CollectionOperationNotVerifiedError extends CollectionOpLogCrudServiceError {
  constructor(reason: string) {
    super(`Collection-Operation wurde uebertragen, aber nicht lokal verifiziert: ${reason}`);
  }
}

export class MissingCollectionBaseMetadataError extends CollectionOpLogCrudServiceError {
  constructor() {
    super('Verifizierte Collection-Basis-Metadaten fehlen. Die Operation wird fail-closed blockiert.');
  }
}

export interface CollectionOpLogCrudDependencies {
  readonly collectionId: string;
  readonly actorUserId: string;
  readonly actorVaultId: string;
  readonly authorDeviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly collectionKey: Uint8Array;
  readonly trustEpoch: number;
  readonly keyVersion: number;
  readonly rpcClient: SupabaseRpcClient;
}

export interface CollectionRecordBase {
  readonly recordVersion: number;
  readonly ciphertextHash: string;
  readonly baseCollectionHead: string | null;
}

export interface SubmitAndVerifyCollectionInput {
  readonly opType: 'create' | 'update' | 'delete' | 'restore' | 'rekey' | 'add_member' | 'remove_member' | 'update_member_permission';
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly plaintext: Record<string, unknown>;
  readonly base: CollectionRecordBase | null;
  readonly membership?: {
    readonly targetUserId: string;
    readonly targetPermission?: 'view' | 'edit';
  };
  readonly keyEnvelope?: {
    readonly recipientUserId: string;
    readonly keyVersion: number;
    readonly wrappedKey: string;
    readonly pqWrappedKey: string;
  };
}

export async function submitAndVerifyCollectionMutation(
  deps: CollectionOpLogCrudDependencies,
  input: SubmitAndVerifyCollectionInput,
): Promise<LocalCollectionState> {
  const isCreate = input.opType === 'create';
  if (!isCreate && (!input.base || !input.base.baseCollectionHead)) {
    throw new MissingCollectionBaseMetadataError();
  }

  const built = await buildCollectionOperation({
    opId: randomUuid(),
    collectionId: deps.collectionId,
    actorUserId: deps.actorUserId,
    actorVaultId: deps.actorVaultId,
    authorDeviceId: deps.authorDeviceId,
    deviceSigningKey: deps.deviceSigningKey,
    opType: input.opType,
    recordId: input.recordId,
    recordType: input.recordType,
    collectionKey: deps.collectionKey,
    plaintext: canonicalizeVaultStructure(input.plaintext),
    keyVersion: deps.keyVersion,
    baseRecordVersion: input.base?.recordVersion ?? null,
    previousCiphertextHash: input.base?.ciphertextHash ?? null,
    baseCollectionHead: input.base?.baseCollectionHead ?? null,
    trustEpoch: deps.trustEpoch,
    membership: input.membership,
    keyEnvelope: input.keyEnvelope,
  });

  const result = await submitCollectionOperation(deps.rpcClient, built);
  if (result.kind !== 'applied') {
    throw new CollectionOpLogCrudServiceError(`Collection-Operation fehlgeschlagen: ${result.kind}`);
  }

  const state = await reloadAndVerifyCollection(deps);
  const verifiedRecord = state.recordsById.get(input.recordId);
  const expectedDeleted = input.opType === 'delete' || input.opType === 'remove_member';
  if (!verifiedRecord) {
    throw new CollectionOperationNotVerifiedError('record missing after reload');
  }
  if (expectedDeleted && verifiedRecord.state !== 'deletedByTrustedDevice') {
    throw new CollectionOperationNotVerifiedError('record not verified as deleted after reload');
  }
  if (!expectedDeleted && verifiedRecord.state !== 'verified') {
    throw new CollectionOperationNotVerifiedError('record not verified as active after reload');
  }
  return state;
}

export async function reloadAndVerifyCollection(
  deps: CollectionOpLogCrudDependencies,
): Promise<LocalCollectionState> {
  const operations = await getCollectionChangesSince(deps.rpcClient, deps.collectionId, 0);
  const recordIds = [...new Set(operations.map((operation) => operation.recordId))];
  const records = await getCollectionRecordsByIds(deps.rpcClient, deps.collectionId, recordIds);
  const authorUserIds = [...new Set(operations.map((operation) => operation.actorUserId))];
  const trustMaterial = await getCollectionAuthorTrustMaterial(deps.rpcClient, deps.collectionId, authorUserIds);
  return buildVerifiedCollectionState({
    operations,
    records,
    trustMaterial,
    collectionKey: deps.collectionKey,
  });
}

export async function getVerifiedCollectionBase(
  deps: CollectionOpLogCrudDependencies,
  state: LocalCollectionState,
  recordId: string,
): Promise<CollectionRecordBase> {
  const head = await getCollectionHead(deps.rpcClient, deps.collectionId);
  const record = state.recordsById.get(recordId);
  if (!head || !record || record.state !== 'verified') {
    throw new MissingCollectionBaseMetadataError();
  }
  return {
    recordVersion: record.record.recordVersion,
    ciphertextHash: record.record.ciphertextHash,
    baseCollectionHead: head.currentHead,
  };
}
