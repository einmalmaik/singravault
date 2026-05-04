// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Operation Builder for the vault operation log (Phase 4).
 *
 * Builds fully signed, canonicalised and hashed vault operations
 * from local verified inputs. Reuses Phase 1 crypto modules:
 * - Record key derivation (`deriveRecordKey`)
 * - AEAD seal (`sealRecord`)
 * - Canonical signed body (`buildOperationSignedBody`)
 * - Device signing (`signOperation`)
 * - Hash computation (`computeOpHash`, `computeVaultHead`)
 *
 * The builder never implements low-level crypto itself. It only
 * orchestrates existing primitives into complete operations.
 *
 * Supported:
 *   - create  (seals a new record, version = 1)
 *   - update  (seals a new version, CAS via previousCiphertextHash)
 *   - delete  (seals a tombstone record, version = base + 1)
 *
 * Restore is documented as intentionally not implemented in Phase 4
 * because no restore-specific plaintext schema exists yet. Callers
 * that need restore can use `update` semantics (new version of an
 * existing record) as an interim path, or extend this module once
 * the restore schema is defined.
 */

import {
  canonicalizeVaultStructure,
} from './canonicalJson';
import {
  deriveRecordKey,
  sealRecord,
} from './cryptoRecordService';
import {
  buildOperationSignedBody,
  signOperation,
} from './operationSigningService';
import {
  computeVaultHead,
} from './recordHashes';
import {
  isRecordType,
  type RecordType,
  type SealedRecordV1,
  type SignedVaultOperationV1,
} from './types';
import type {
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';

export class VaultOperationBuilderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultOperationBuilderError';
  }
}

// ---------------------------------------------------------------------------
// Builder output
// ---------------------------------------------------------------------------

export interface BuiltVaultOperation {
  readonly signedOperation: SignedVaultOperationV1;
  readonly resultingVaultHead: string;
  readonly sealedRecord: SealedRecordV1;
}

// ---------------------------------------------------------------------------
// Shared base input
// ---------------------------------------------------------------------------

export interface BaseOperationBuilderInput {
  readonly opId: string;
  readonly intentId: string;
  readonly rebasedFromOpId: string | null;
  readonly vaultId: string;
  readonly recordId: string;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly trustEpoch: number;
  readonly baseVaultHead: string | null;
  readonly createdAtClient?: string;
}

// ---------------------------------------------------------------------------
// Per-operation inputs
// ---------------------------------------------------------------------------

export interface CreateRecordBuilderInput extends BaseOperationBuilderInput {
  readonly recordType: Exclude<RecordType, 'tombstone'>;
  readonly vaultEncryptionKey: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly keyVersion: number;
}

export interface UpdateRecordBuilderInput extends BaseOperationBuilderInput {
  readonly recordType: RecordType;
  readonly vaultEncryptionKey: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly keyVersion: number;
  readonly baseRecordVersion: number;
  readonly previousCiphertextHash: string;
}

export interface DeleteRecordBuilderInput extends BaseOperationBuilderInput {
  readonly recordType: RecordType;
  readonly vaultEncryptionKey: Uint8Array;
  readonly keyVersion: number;
  readonly baseRecordVersion: number;
  readonly previousCiphertextHash: string;
}

export interface RestoreRecordBuilderInput extends BaseOperationBuilderInput {
  readonly recordType: RecordType;
  readonly vaultEncryptionKey: Uint8Array;
  readonly plaintext: Uint8Array;
  readonly keyVersion: number;
  readonly baseRecordVersion: number;
  readonly previousCiphertextHash: string;
}

// ---------------------------------------------------------------------------
// Public builder functions
// ---------------------------------------------------------------------------

/**
 * Build a `create` operation for a new vault record.
 *
 * - `baseRecordVersion` is set to `null`.
 * - `previousCiphertextHash` is set to `null`.
 * - `recordVersion` in the sealed record is always `1`.
 */
export async function buildCreateRecordOperation(
  input: CreateRecordBuilderInput,
): Promise<BuiltVaultOperation> {
  const createdAtClient = input.createdAtClient ?? new Date().toISOString();

  const sealed = await sealPayload({
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: 1,
    keyVersion: input.keyVersion,
    vaultEncryptionKey: input.vaultEncryptionKey,
    plaintext: input.plaintext,
  });

  const body = buildOperationSignedBody({
    opId: input.opId,
    intentId: input.intentId,
    rebasedFromOpId: input.rebasedFromOpId,
    vaultId: input.vaultId,
    authorDeviceId: input.deviceId,
    opType: 'create',
    recordId: input.recordId,
    recordType: input.recordType,
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: sealed.ciphertextHash,
    baseVaultHead: input.baseVaultHead,
    payloadCiphertextHash: sealed.ciphertextHash,
    payloadAadHash: sealed.aadHash,
    createdAtClient,
    trustEpoch: input.trustEpoch,
  });

  const signed = await signOperation(body, input.deviceSigningKey);

  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: input.baseVaultHead,
    opHash: signed.opHash,
    recordId: input.recordId,
    recordType: input.recordType,
    newRecordHash: sealed.ciphertextHash,
    opType: 'create',
  });

  return { signedOperation: signed, sealedRecord: sealed, resultingVaultHead };
}

/**
 * Build an `update` operation for an existing verified record.
 *
 * - `baseRecordVersion` and `previousCiphertextHash` are taken from
 *   the locally verified record state (CAS basis).
 * - The sealed record uses `recordVersion = baseRecordVersion + 1`.
 */
export async function buildUpdateRecordOperation(
  input: UpdateRecordBuilderInput,
): Promise<BuiltVaultOperation> {
  const createdAtClient = input.createdAtClient ?? new Date().toISOString();

  const nextRecordVersion = input.baseRecordVersion + 1;
  const sealed = await sealPayload({
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    recordVersion: nextRecordVersion,
    keyVersion: input.keyVersion,
    vaultEncryptionKey: input.vaultEncryptionKey,
    plaintext: input.plaintext,
  });

  const body = buildOperationSignedBody({
    opId: input.opId,
    intentId: input.intentId,
    rebasedFromOpId: input.rebasedFromOpId,
    vaultId: input.vaultId,
    authorDeviceId: input.deviceId,
    opType: 'update',
    recordId: input.recordId,
    recordType: input.recordType,
    baseRecordVersion: input.baseRecordVersion,
    previousCiphertextHash: input.previousCiphertextHash,
    newRecordHash: sealed.ciphertextHash,
    baseVaultHead: input.baseVaultHead,
    payloadCiphertextHash: sealed.ciphertextHash,
    payloadAadHash: sealed.aadHash,
    createdAtClient,
    trustEpoch: input.trustEpoch,
  });

  const signed = await signOperation(body, input.deviceSigningKey);

  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: input.baseVaultHead,
    opHash: signed.opHash,
    recordId: input.recordId,
    recordType: input.recordType,
    newRecordHash: sealed.ciphertextHash,
    opType: 'update',
  });

  return { signedOperation: signed, sealedRecord: sealed, resultingVaultHead };
}

/**
 * Build a `delete` operation for an existing verified record.
 *
 * Delete is never a bare row removal. It produces a signed
 * operation and a sealed **tombstone** record whose plaintext is
 * a minimal canonical marker (`{ tombstone: true }`).
 *
 * The operation's `recordType` remains the original type (e.g.
 * `item`). The tombstone record's `recordType` is `tombstone`.
 */
export async function buildDeleteRecordOperation(
  input: DeleteRecordBuilderInput,
): Promise<BuiltVaultOperation> {
  const createdAtClient = input.createdAtClient ?? new Date().toISOString();

  const nextRecordVersion = input.baseRecordVersion + 1;

  // Minimal deterministic tombstone plaintext.
  const tombstonePlaintext = canonicalizeVaultStructure({
    tombstone: true,
    deletedAt: createdAtClient,
  });

  const sealed = await sealPayload({
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: 'tombstone',
    recordVersion: nextRecordVersion,
    keyVersion: input.keyVersion,
    vaultEncryptionKey: input.vaultEncryptionKey,
    plaintext: tombstonePlaintext,
  });

  const body = buildOperationSignedBody({
    opId: input.opId,
    intentId: input.intentId,
    rebasedFromOpId: input.rebasedFromOpId,
    vaultId: input.vaultId,
    authorDeviceId: input.deviceId,
    opType: 'delete',
    recordId: input.recordId,
    recordType: input.recordType,
    baseRecordVersion: input.baseRecordVersion,
    previousCiphertextHash: input.previousCiphertextHash,
    newRecordHash: sealed.ciphertextHash,
    baseVaultHead: input.baseVaultHead,
    payloadCiphertextHash: sealed.ciphertextHash,
    payloadAadHash: sealed.aadHash,
    createdAtClient,
    trustEpoch: input.trustEpoch,
  });

  const signed = await signOperation(body, input.deviceSigningKey);

  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: input.baseVaultHead,
    opHash: signed.opHash,
    recordId: input.recordId,
    recordType: input.recordType,
    newRecordHash: sealed.ciphertextHash,
    opType: 'delete',
  });

  return { signedOperation: signed, sealedRecord: sealed, resultingVaultHead };
}

/**
 * Build a `restore` operation.
 *
 * **Not fully implemented in Phase 4.**
 * Restore semantics are equivalent to an `update` (new version of
 * an existing record) until a dedicated restore plaintext schema is
 * defined. Callers that need restore in Phase 4 should use
 * `buildUpdateRecordOperation` with a plaintext that represents the
 * restored content.
 */
export async function buildRestoreRecordOperation(
  _input: RestoreRecordBuilderInput,
): Promise<BuiltVaultOperation> {
  throw new VaultOperationBuilderError(
    'restore operation builder is not implemented in Phase 4; ' +
    'use update semantics as an interim path',
  );
}

// ---------------------------------------------------------------------------
// Conversion helpers: BuiltVaultOperation -> domain rows
// ---------------------------------------------------------------------------

/**
 * Convert a built operation to a `VaultOperationRow` suitable for
 * the pending queue or RPC submission.
 *
 * `receivedAtServer` defaults to `''` and `sequenceNumber` to `0`
 * because these are server-assigned and not known locally.
 */
export function toVaultOperationRow(
  built: BuiltVaultOperation,
  overrides?: Partial<VaultOperationRow>,
): VaultOperationRow {
  const body = built.signedOperation.body;
  return {
    opId: body.opId,
    opHash: built.signedOperation.opHash,
    vaultId: body.vaultId,
    authorDeviceId: body.authorDeviceId,
    opType: body.opType,
    recordId: body.recordId,
    recordType: body.recordType,
    baseRecordVersion: body.baseRecordVersion,
    previousCiphertextHash: body.previousCiphertextHash,
    newRecordHash: body.newRecordHash,
    baseVaultHead: body.baseVaultHead,
    resultingVaultHead: built.resultingVaultHead,
    intentId: body.intentId,
    rebasedFromOpId: body.rebasedFromOpId,
    payloadCiphertextHash: body.payloadCiphertextHash,
    payloadAadHash: body.payloadAadHash,
    signedBody: body,
    signature: built.signedOperation.signature,
    signatureSchema: body.signatureSchema,
    trustEpoch: body.trustEpoch,
    createdAtClient: body.createdAtClient,
    receivedAtServer: '',
    sequenceNumber: 0,
    ...overrides,
  };
}

/**
 * Convert a sealed record to a `VaultRecordRow`.
 *
 * `lastOpId` / `lastOpHash` are taken from the accompanying
 * operation. `createdAt` / `updatedAt` default to the operation's
 * `createdAtClient`.
 */
export function toVaultRecordRow(
  sealed: SealedRecordV1,
  op: VaultOperationRow,
  isTombstone: boolean,
  overrides?: Partial<VaultRecordRow>,
): VaultRecordRow {
  return {
    vaultId: op.vaultId,
    recordId: sealed.aad.recordId,
    recordType: sealed.aad.recordType,
    recordVersion: sealed.aad.recordVersion,
    keyVersion: sealed.aad.keyVersion,
    aadHash: sealed.aadHash,
    ciphertextHash: sealed.ciphertextHash,
    nonce: sealed.nonceB64Url,
    ciphertext: sealed.ciphertextB64Url,
    lastOpId: op.opId,
    lastOpHash: op.opHash,
    isTombstone,
    createdAt: op.createdAtClient,
    updatedAt: op.createdAtClient,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function sealPayload(args: {
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: RecordType;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly vaultEncryptionKey: Uint8Array;
  readonly plaintext: Uint8Array;
}): Promise<SealedRecordV1> {
  if (!isRecordType(args.recordType)) {
    throw new VaultOperationBuilderError(`invalid recordType: ${String(args.recordType)}`);
  }

  const recordKey = await deriveRecordKey({
    vaultEncryptionKey: args.vaultEncryptionKey,
    vaultId: args.vaultId,
    recordId: args.recordId,
    recordType: args.recordType,
    keyVersion: args.keyVersion,
  });

  try {
    return await sealRecord({
      plaintext: args.plaintext,
      recordKey,
      aadInput: {
        vaultId: args.vaultId,
        recordId: args.recordId,
        recordType: args.recordType,
        recordVersion: args.recordVersion,
        keyVersion: args.keyVersion,
      },
    });
  } finally {
    // Wipe derived key from memory (best effort)
    recordKey.fill(0);
  }
}
