// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export const COLLECTION_RECORD_TYPES = [
  'collection_metadata',
  'collection_member',
  'collection_item',
  'collection_key',
  'tombstone',
] as const;

export type CollectionRecordType = (typeof COLLECTION_RECORD_TYPES)[number];

export function isCollectionRecordType(value: unknown): value is CollectionRecordType {
  return typeof value === 'string' && (COLLECTION_RECORD_TYPES as readonly string[]).includes(value);
}

export const COLLECTION_OPERATION_TYPES = [
  'create',
  'update',
  'delete',
  'restore',
  'rekey',
  'add_member',
  'remove_member',
  'update_member_permission',
] as const;

export type CollectionOperationType = (typeof COLLECTION_OPERATION_TYPES)[number];

export function isCollectionOperationType(value: unknown): value is CollectionOperationType {
  return typeof value === 'string' && (COLLECTION_OPERATION_TYPES as readonly string[]).includes(value);
}

export const COLLECTION_AAD_SCHEMA_V1 = 'collection-record-aad-v1' as const;
export const COLLECTION_ENCRYPTION_SCHEMA_V1 = 'collection-record-aead-v1' as const;
export const COLLECTION_SIGNATURE_SCHEMA_V1 = 'device-signature-v1' as const;

export interface CollectionRecordAadV1 {
  readonly app: 'singra-vault';
  readonly aadSchema: typeof COLLECTION_AAD_SCHEMA_V1;
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly encryptionSchema: typeof COLLECTION_ENCRYPTION_SCHEMA_V1;
}

export interface CollectionOperationSignedBodyV1 {
  readonly signatureSchema: typeof COLLECTION_SIGNATURE_SCHEMA_V1;
  readonly opId: string;
  readonly collectionId: string;
  readonly actorUserId: string;
  readonly actorVaultId: string;
  readonly authorDeviceId: string;
  readonly opType: CollectionOperationType;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly baseRecordVersion: number | null;
  readonly previousCiphertextHash: string | null;
  readonly newRecordHash: string | null;
  readonly baseCollectionHead: string | null;
  readonly payloadCiphertextHash: string | null;
  readonly payloadAadHash: string | null;
  readonly createdAtClient: string;
  readonly trustEpoch: number;
}

export interface SignedCollectionOperationV1 {
  readonly body: CollectionOperationSignedBodyV1;
  readonly signature: string;
  readonly opHash: string;
}

export interface SealedCollectionRecordV1 {
  readonly aad: CollectionRecordAadV1;
  readonly aadHash: string;
  readonly nonceB64Url: string;
  readonly ciphertextB64Url: string;
  readonly ciphertextHash: string;
}

export interface CollectionRecordRow {
  readonly collectionId: string;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
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

export interface CollectionOperationRow {
  readonly opId: string;
  readonly opHash: string;
  readonly collectionId: string;
  readonly actorUserId: string;
  readonly actorVaultId: string;
  readonly authorDeviceId: string;
  readonly opType: CollectionOperationType;
  readonly recordId: string;
  readonly recordType: CollectionRecordType;
  readonly baseRecordVersion: number | null;
  readonly previousCiphertextHash: string | null;
  readonly newRecordHash: string | null;
  readonly baseCollectionHead: string | null;
  readonly resultingCollectionHead: string;
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

export interface CollectionHeadRow {
  readonly collectionId: string;
  readonly currentHead: string | null;
  readonly currentOpId: string | null;
  readonly currentSequenceNumber: number;
  readonly updatedAt: string;
}

export interface CollectionKeyEnvelopeRow {
  readonly collectionId: string;
  readonly userId: string;
  readonly keyVersion: number;
  readonly wrappedKey: string;
  readonly pqWrappedKey: string;
  readonly updatedAt: string;
}

export interface CollectionTrustedAuthorDevice {
  readonly userId: string;
  readonly vaultId: string;
  readonly deviceId: string;
  readonly publicSigningKey: string;
  readonly trustEpoch: number;
  readonly status: 'trusted' | 'revoked';
}

export type CollectionSecurityState =
  | 'verified'
  | 'deletedByTrustedDevice'
  | 'quarantinedTampered'
  | 'quarantinedUnknownAuthor'
  | 'quarantinedUnreadable'
  | 'quarantinedInvalidSchema'
  | 'conflict';

export class CollectionOpLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CollectionOpLogError';
  }
}
