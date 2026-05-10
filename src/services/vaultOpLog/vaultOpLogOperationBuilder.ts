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
 *   - delete  (seals a typed tombstone payload, version = base + 1)
 *
 * Restore is documented as intentionally not implemented in Phase 4
 * because no restore-specific plaintext schema exists yet. Callers
 * that need restore can use `update` semantics (new version of an
 * existing record) as an interim path, or extend this module once
 * the restore schema is defined.
 */

import {
  canonicalizeVaultStructure,
  decodeBase64Url,
  encodeBase64Url,
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

export interface AddDeviceBuilderInput {
  readonly opId: string;
  readonly intentId: string;
  readonly rebasedFromOpId: string | null;
  readonly vaultId: string;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly trustEpoch: number;
  readonly baseVaultHead: string | null;
  readonly createdAtClient?: string;
  /** The device ID that will be added (target device's unique ID) */
  readonly targetDeviceId: string;
  /** The public signing key of the target device (SPKI, base64url) */
  readonly targetPublicSigningKey: string;
  /** Human-readable name for the target device */
  readonly targetDeviceName: string;
  /** Platform identifier for the target device (optional) */
  readonly targetDevicePlatform?: string;
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
 * operation and a sealed typed tombstone payload whose plaintext is
 * a minimal canonical marker (`{ tombstone: true }`).
 *
 * The record AAD keeps the original type (for example `item`), while
 * the DB row marks `is_tombstone = true`. Keeping the logical type in
 * AAD preserves restore/update CAS checks for the same physical row.
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
    recordType: input.recordType,
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
 * Build a `restore` operation (Phase 6).
 *
 * Restore semantics are equivalent to an `update` (new version of
 * an existing record) with `opType = 'restore'`.  The caller
 * supplies the plaintext recovered from a verified snapshot or other
 * trusted source.  The record is re-sealed with a fresh nonce,
 * current keyVersion, and recordVersion = baseRecordVersion + 1.
 */
export async function buildRestoreRecordOperation(
  input: RestoreRecordBuilderInput,
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
    opType: 'restore',
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
    opType: 'restore',
  });

  return { signedOperation: signed, sealedRecord: sealed, resultingVaultHead };
}

/**
 * Build an `add_device` operation.
 *
 * This operation is signed by an **existing** trusted device and
 * authorises the addition of a new device to the vault's trust list.
 * The signing device's private key is used to bind the operation to
 * its identity.
 *
 * The target device is identified by:
 * - `targetDeviceId` – stable unique identifier (UUID, fingerprint, etc.)
 * - `targetPublicSigningKey` – SPKI, base64url-encoded public key
 *
 * The `add_device` operation does **not** carry a sealed record
 * (unlike create/update/delete) because it is a trust metadata
 * operation. The recordId is set to `targetDeviceId` and the
 * recordType to `'device'` to keep the structure consistent with
 * the signed body schema.
 *
 * The server will verify:
 * 1. The operation is a valid `SignedVaultOperationV1`.
 * 2. The author is an **existing** trusted device for the vault.
 * 3. The signature is valid against the author's public key.
 * 4. The target device ID and public key match the corresponding
 *    pending device request (if applicable).
 *
 * **Security note**: A valid `add_device` operation alone does NOT
 * create trust. Trust is only established after the operation is
 * committed via `submit_vault_operation` and the client-side
 * `deviceTrustService.classifyOperationAuthor` confirms the author
 * is trusted.
 */
export async function buildAddDeviceOperation(
  input: AddDeviceBuilderInput,
): Promise<{
  readonly signedOperation: SignedVaultOperationV1;
  readonly resultingVaultHead: string;
  readonly targetDeviceId: string;
  readonly targetPublicSigningKey: string;
  readonly targetDeviceName: string;
  readonly targetDevicePlatform: string | null;
}> {
  const createdAtClient = input.createdAtClient ?? new Date().toISOString();

  // Compute fingerprint of target public key for quick verification
  const targetDeviceKeyFingerprint = await computePublicKeyFingerprint(input.targetPublicSigningKey);

  // For add_device, we use targetDeviceId as the recordId and 'device' as recordType
  // to maintain consistency with the signed body schema.
  // baseRecordVersion and previousCiphertextHash are null because add_device
  // does not follow the record versioning scheme.
  //
  // SECURITY: targetPublicSigningKey and targetDeviceKeyFingerprint are CRITICAL
  // and MUST be included in the signed body to prevent MITM attacks.
  const body = buildOperationSignedBody({
    opId: input.opId,
    intentId: input.intentId,
    rebasedFromOpId: input.rebasedFromOpId,
    vaultId: input.vaultId,
    authorDeviceId: input.deviceId,
    opType: 'add_device',
    recordId: input.targetDeviceId,
    recordType: 'device',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: null,
    baseVaultHead: input.baseVaultHead,
    payloadCiphertextHash: null,
    payloadAadHash: null,
    createdAtClient,
    trustEpoch: input.trustEpoch,
    // SECURITY CRITICAL: These fields are now part of the signed body
    targetPublicSigningKey: input.targetPublicSigningKey,
    targetDeviceKeyFingerprint,
  });

  const signed = await signOperation(body, input.deviceSigningKey);

  // For add_device, we compute the vault head normally since it is
  // still part of the vault operation chain.
  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: input.baseVaultHead,
    opHash: signed.opHash,
    recordId: input.targetDeviceId,
    recordType: 'device',
    newRecordHash: null,
    opType: 'add_device',
  });

  return {
    signedOperation: signed,
    resultingVaultHead,
    targetDeviceId: input.targetDeviceId,
    targetPublicSigningKey: input.targetPublicSigningKey,
    targetDeviceName: input.targetDeviceName,
    targetDevicePlatform: input.targetDevicePlatform ?? null,
  };
}

export type BuiltAddDeviceOperation = Awaited<ReturnType<typeof buildAddDeviceOperation>>;


// --------------------------------------------------------------------------
// Compute public key fingerprint (used by add_device)
// --------------------------------------------------------------------------

async function computePublicKeyFingerprint(publicKeyB64Url: string): Promise<string> {
  const keyBytes = decodeBase64Url(publicKeyB64Url);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytes as unknown as ArrayBuffer);
  return encodeBase64Url(new Uint8Array(hashBuffer));
}

// ---------------------------------------------------------------------------
// Conversion helpers: BuiltVaultOperation -> domain rows
// --------------------------------------------------------------------------

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
  return toVaultOperationRowFromSigned(
    built.signedOperation,
    built.resultingVaultHead,
    overrides,
  );
}

export function toVaultOperationRowFromSigned(
  signedOperation: SignedVaultOperationV1,
  resultingVaultHead: string,
  overrides?: Partial<VaultOperationRow>,
): VaultOperationRow {
  const body = signedOperation.body;
  return {
    opId: body.opId,
    opHash: signedOperation.opHash,
    vaultId: body.vaultId,
    authorDeviceId: body.authorDeviceId,
    opType: body.opType,
    recordId: body.recordId,
    recordType: body.recordType,
    baseRecordVersion: body.baseRecordVersion,
    previousCiphertextHash: body.previousCiphertextHash,
    newRecordHash: body.newRecordHash,
    baseVaultHead: body.baseVaultHead,
    resultingVaultHead,
    intentId: body.intentId,
    rebasedFromOpId: body.rebasedFromOpId,
    payloadCiphertextHash: body.payloadCiphertextHash,
    payloadAadHash: body.payloadAadHash,
    signedBody: body,
    signature: signedOperation.signature,
    signatureSchema: body.signatureSchema,
    trustEpoch: body.trustEpoch,
    createdAtClient: body.createdAtClient,
    receivedAtServer: '',
    sequenceNumber: 0,
    ...overrides,
  };
}

export function buildAddDeviceTrustPayload(
  built: BuiltAddDeviceOperation,
  authorDeviceId: string,
): {
  readonly kind: 'add';
  readonly device: {
    readonly device_id: string;
    readonly public_signing_key: string;
    readonly device_name_encrypted: string;
    readonly added_by_device_id: string;
    readonly added_at: string;
    readonly trust_epoch: number;
  };
} {
  const body = built.signedOperation.body;
  return {
    kind: 'add',
    device: {
      device_id: built.targetDeviceId,
      public_signing_key: built.targetPublicSigningKey,
      device_name_encrypted: '',
      added_by_device_id: authorDeviceId,
      added_at: body.createdAtClient,
      trust_epoch: 0,
    },
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

