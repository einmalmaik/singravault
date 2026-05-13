// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { canonicalizeVaultStructure, decodeBase64Url } from '@/services/vaultOpLog/canonicalJson';
import { importDevicePublicKey } from '@/services/vaultOpLog/operationSigningService';
import { openVerifiedCollectionRecord } from './crypto';
import { computeCollectionHead, computeCollectionOpHash } from './operationBuilder';
import {
  COLLECTION_SIGNATURE_SCHEMA_V1,
  type CollectionOperationRow,
  type CollectionOperationSignedBodyV1,
  type CollectionRecordRow,
  type CollectionSecurityState,
  type CollectionTrustedAuthorDevice,
  type SealedCollectionRecordV1,
} from './types';

export interface LocalCollectionRecord {
  readonly record: CollectionRecordRow;
  readonly state: CollectionSecurityState;
  readonly plaintext: Uint8Array | null;
  readonly lastOperation: CollectionOperationRow;
}

export interface LocalCollectionState {
  readonly recordsById: ReadonlyMap<string, LocalCollectionRecord>;
  readonly quarantinedRecordsById: ReadonlyMap<string, LocalCollectionRecord>;
  readonly lastVerifiedCollectionHead: string | null;
}

export const EMPTY_COLLECTION_STATE: LocalCollectionState = {
  recordsById: new Map(),
  quarantinedRecordsById: new Map(),
  lastVerifiedCollectionHead: null,
};

export async function buildVerifiedCollectionState(input: {
  readonly operations: readonly CollectionOperationRow[];
  readonly records: readonly CollectionRecordRow[];
  readonly trustMaterial: readonly CollectionTrustedAuthorDevice[];
  readonly collectionKey: Uint8Array;
}): Promise<LocalCollectionState> {
  let state: LocalCollectionState = EMPTY_COLLECTION_STATE;
  const recordsById = new Map(input.records.map((record) => [record.recordId, record]));
  const trustByDeviceId = new Map(input.trustMaterial.map((device) => [device.deviceId, device]));

  for (const operation of [...input.operations].sort((a, b) => a.sequenceNumber - b.sequenceNumber)) {
    const record = recordsById.get(operation.recordId);
    if (!record) {
      state = quarantine(state, operation, null, 'quarantinedTampered');
      continue;
    }

    const trustedDevice = trustByDeviceId.get(operation.authorDeviceId);
    if (!trustedDevice || trustedDevice.status !== 'trusted' || trustedDevice.trustEpoch !== operation.trustEpoch) {
      state = quarantine(state, operation, record, 'quarantinedUnknownAuthor');
      continue;
    }

    if (!signedBodyMatchesOperation(operation)) {
      state = quarantine(state, operation, record, 'quarantinedTampered');
      continue;
    }

    const opHash = await computeCollectionOpHash(operation.signedBody as CollectionOperationSignedBodyV1);
    if (opHash !== operation.opHash || !(await verifyCollectionOperationSignature(operation, trustedDevice.publicSigningKey))) {
      state = quarantine(state, operation, record, 'quarantinedTampered');
      continue;
    }

    const expectedHead = await computeCollectionHead({
      previousCollectionHead: state.lastVerifiedCollectionHead,
      opHash: operation.opHash,
      recordId: operation.recordId,
      recordType: operation.recordType,
      newRecordHash: operation.newRecordHash,
      opType: operation.opType,
    });
    if (expectedHead !== operation.resultingCollectionHead) {
      state = quarantine(state, operation, record, 'quarantinedTampered');
      continue;
    }

    if (record.lastOpId !== operation.opId || record.lastOpHash !== operation.opHash) {
      state = quarantine(state, operation, record, 'quarantinedTampered');
      continue;
    }

    if (operation.payloadCiphertextHash !== record.ciphertextHash || operation.payloadAadHash !== record.aadHash) {
      state = quarantine(state, operation, record, 'quarantinedTampered');
      continue;
    }

    let plaintext: Uint8Array | null = null;
    try {
      plaintext = await openVerifiedCollectionRecord({
        sealed: sealedFromRecord(record),
        collectionKey: input.collectionKey,
        expected: {
          collectionId: record.collectionId,
          recordId: record.recordId,
          recordType: record.recordType,
          recordVersion: record.recordVersion,
          keyVersion: record.keyVersion,
        },
        expectedAadHash: record.aadHash,
        expectedCiphertextHash: record.ciphertextHash,
      });
    } catch {
      state = quarantine(state, operation, record, 'quarantinedUnreadable');
      continue;
    }

    if (!isValidCollectionPlaintext(plaintext)) {
      state = quarantine(state, operation, record, 'quarantinedInvalidSchema');
      continue;
    }

    state = verify(state, operation, record, plaintext);
  }

  return state;
}

function sealedFromRecord(record: CollectionRecordRow): SealedCollectionRecordV1 {
  return {
    aad: {
      app: 'singra-vault',
      aadSchema: 'collection-record-aad-v1',
      collectionId: record.collectionId,
      recordId: record.recordId,
      recordType: record.recordType,
      recordVersion: record.recordVersion,
      keyVersion: record.keyVersion,
      encryptionSchema: 'collection-record-aead-v1',
    },
    aadHash: record.aadHash,
    nonceB64Url: record.nonce,
    ciphertextB64Url: record.ciphertext,
    ciphertextHash: record.ciphertextHash,
  };
}

async function verifyCollectionOperationSignature(
  operation: CollectionOperationRow,
  publicSigningKey: string,
): Promise<boolean> {
  if (operation.signatureSchema !== COLLECTION_SIGNATURE_SCHEMA_V1) return false;
  const publicKey = await importDevicePublicKey(publicSigningKey);
  const signature = decodeBase64Url(operation.signature);
  if (signature.length !== 64) return false;
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signature as unknown as ArrayBuffer,
    canonicalizeVaultStructure(operation.signedBody) as unknown as ArrayBuffer,
  );
}

function signedBodyMatchesOperation(operation: CollectionOperationRow): boolean {
  const body = operation.signedBody;
  if (!isCollectionOperationSignedBody(body)) return false;

  return body.signatureSchema === operation.signatureSchema
    && body.opId === operation.opId
    && body.collectionId === operation.collectionId
    && body.actorUserId === operation.actorUserId
    && body.actorVaultId === operation.actorVaultId
    && body.authorDeviceId === operation.authorDeviceId
    && body.opType === operation.opType
    && body.recordId === operation.recordId
    && body.recordType === operation.recordType
    && body.baseRecordVersion === operation.baseRecordVersion
    && body.previousCiphertextHash === operation.previousCiphertextHash
    && body.newRecordHash === operation.newRecordHash
    && body.baseCollectionHead === operation.baseCollectionHead
    && body.payloadCiphertextHash === operation.payloadCiphertextHash
    && body.payloadAadHash === operation.payloadAadHash
    && body.createdAtClient === operation.createdAtClient
    && body.trustEpoch === operation.trustEpoch;
}

function isCollectionOperationSignedBody(value: unknown): value is CollectionOperationSignedBodyV1 {
  if (!value || typeof value !== 'object') return false;
  const body = value as Partial<CollectionOperationSignedBodyV1>;
  return body.signatureSchema === COLLECTION_SIGNATURE_SCHEMA_V1
    && typeof body.opId === 'string'
    && typeof body.collectionId === 'string'
    && typeof body.actorUserId === 'string'
    && typeof body.actorVaultId === 'string'
    && typeof body.authorDeviceId === 'string'
    && typeof body.opType === 'string'
    && typeof body.recordId === 'string'
    && typeof body.recordType === 'string'
    && (typeof body.baseRecordVersion === 'number' || body.baseRecordVersion === null)
    && (typeof body.previousCiphertextHash === 'string' || body.previousCiphertextHash === null)
    && (typeof body.newRecordHash === 'string' || body.newRecordHash === null)
    && (typeof body.baseCollectionHead === 'string' || body.baseCollectionHead === null)
    && (typeof body.payloadCiphertextHash === 'string' || body.payloadCiphertextHash === null)
    && (typeof body.payloadAadHash === 'string' || body.payloadAadHash === null)
    && typeof body.createdAtClient === 'string'
    && Number.isSafeInteger(body.trustEpoch);
}

function verify(
  state: LocalCollectionState,
  operation: CollectionOperationRow,
  record: CollectionRecordRow,
  plaintext: Uint8Array,
): LocalCollectionState {
  const recordsById = new Map(state.recordsById);
  recordsById.set(record.recordId, {
    record,
    state: record.isTombstone ? 'deletedByTrustedDevice' : 'verified',
    plaintext,
    lastOperation: operation,
  });
  return {
    recordsById,
    quarantinedRecordsById: state.quarantinedRecordsById,
    lastVerifiedCollectionHead: operation.resultingCollectionHead,
  };
}

function quarantine(
  state: LocalCollectionState,
  operation: CollectionOperationRow,
  record: CollectionRecordRow | null,
  recordState: CollectionSecurityState,
): LocalCollectionState {
  if (!record) return state;
  const quarantinedRecordsById = new Map(state.quarantinedRecordsById);
  quarantinedRecordsById.set(record.recordId, {
    record,
    state: recordState,
    plaintext: null,
    lastOperation: operation,
  });
  return {
    ...state,
    quarantinedRecordsById,
  };
}

function isValidCollectionPlaintext(plaintext: Uint8Array): boolean {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    return Boolean(parsed && typeof parsed === 'object' && !Array.isArray(parsed));
  } catch {
    return false;
  }
}
