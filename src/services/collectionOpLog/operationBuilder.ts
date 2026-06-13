// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { signEcdsaP256 } from '@msdis/shield/signing';
import { canonicalizeVaultStructure, encodeBase64Url } from '@/services/vaultOpLog/canonicalJson';
import { sha256Base64Url } from '@/services/vaultOpLog/recordHashes';
import { sealCollectionRecord } from './crypto';
import {
  COLLECTION_SIGNATURE_SCHEMA_V1,
  isCollectionOperationType,
  isCollectionRecordType,
  type CollectionOperationSignedBodyV1,
  type CollectionOperationType,
  type CollectionRecordType,
  type SealedCollectionRecordV1,
  type SignedCollectionOperationV1,
} from './types';

export interface BuiltCollectionOperation {
  readonly signedOperation: SignedCollectionOperationV1;
  readonly resultingCollectionHead: string;
  readonly sealedRecord: SealedCollectionRecordV1;
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

export interface BuildCollectionOperationInput {
  readonly opId: string;
  readonly collectionId: string;
  readonly actorUserId: string;
  readonly actorVaultId: string;
  readonly authorDeviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly opType: CollectionOperationType;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly collectionKey: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly keyVersion: number;
  readonly baseRecordVersion: number | null;
  readonly previousCiphertextHash: string | null;
  readonly baseCollectionHead: string | null;
  readonly trustEpoch: number;
  readonly createdAtClient?: string;
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

export async function buildCollectionOperation(
  input: BuildCollectionOperationInput,
): Promise<BuiltCollectionOperation> {
  if (!isCollectionOperationType(input.opType)) {
    throw new Error(`unknown collection op type: ${input.opType}`);
  }
  if (!isCollectionRecordType(input.recordType)) {
    throw new Error(`unknown collection record type: ${input.recordType}`);
  }
  const recordVersion = input.baseRecordVersion === null ? 1 : input.baseRecordVersion + 1;
  const plaintext = input.opType === 'delete' || input.opType === 'remove_member'
    ? canonicalizeVaultStructure({ tombstone: true })
    : input.plaintext;
  const sealedRecord = await sealCollectionRecord({
    plaintext,
    collectionKey: input.collectionKey,
    collectionId: input.collectionId,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion,
    keyVersion: input.keyVersion,
  });
  const body = buildCollectionOperationSignedBody({
    signatureSchema: COLLECTION_SIGNATURE_SCHEMA_V1,
    opId: input.opId,
    collectionId: input.collectionId,
    actorUserId: input.actorUserId,
    actorVaultId: input.actorVaultId,
    authorDeviceId: input.authorDeviceId,
    opType: input.opType,
    recordId: input.recordId,
    recordType: input.recordType,
    baseRecordVersion: input.baseRecordVersion,
    previousCiphertextHash: input.previousCiphertextHash,
    newRecordHash: sealedRecord.ciphertextHash,
    baseCollectionHead: input.baseCollectionHead,
    payloadCiphertextHash: sealedRecord.ciphertextHash,
    payloadAadHash: sealedRecord.aadHash,
    createdAtClient: input.createdAtClient ?? new Date().toISOString(),
    trustEpoch: input.trustEpoch,
  });
  const signed = await signCollectionOperation(body, input.deviceSigningKey);
  const resultingCollectionHead = await computeCollectionHead({
    previousCollectionHead: input.baseCollectionHead,
    opHash: signed.opHash,
    recordId: input.recordId,
    recordType: input.recordType,
    newRecordHash: sealedRecord.ciphertextHash,
    opType: input.opType,
  });
  return {
    signedOperation: signed,
    sealedRecord,
    resultingCollectionHead,
    membership: input.membership,
    keyEnvelope: input.keyEnvelope,
  };
}

export function buildCollectionOperationSignedBody(
  body: CollectionOperationSignedBodyV1,
): CollectionOperationSignedBodyV1 {
  if (!isCollectionOperationType(body.opType) || !isCollectionRecordType(body.recordType)) {
    throw new Error('invalid collection operation signed body');
  }
  if (!Number.isSafeInteger(body.trustEpoch) || body.trustEpoch < 0) {
    throw new Error('trustEpoch must be a non-negative safe integer');
  }
  return body;
}

export async function signCollectionOperation(
  body: CollectionOperationSignedBodyV1,
  privateKey: CryptoKey,
): Promise<SignedCollectionOperationV1> {
  const bytes = canonicalizeVaultStructure(body);
  const signatureBytes = await signEcdsaP256(privateKey, bytes);
  return {
    body,
    signature: encodeBase64Url(signatureBytes),
    opHash: await computeCollectionOpHash(body),
  };
}

export async function computeCollectionOpHash(body: CollectionOperationSignedBodyV1): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    schema: 'collection-op-hash-v1',
    body,
  }));
}

export async function computeCollectionHead(input: {
  readonly previousCollectionHead: string | null;
  readonly opHash: string;
  readonly recordId: string;
  readonly recordType: string;
  readonly newRecordHash: string | null;
  readonly opType: string;
}): Promise<string> {
  return sha256Base64Url(canonicalizeVaultStructure({
    schema: 'collection-head-v1',
    newRecordHash: input.newRecordHash,
    opHash: input.opHash,
    opType: input.opType,
    previousCollectionHead: input.previousCollectionHead,
    recordId: input.recordId,
    recordType: input.recordType,
  }));
}
