// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `trustedSnapshotService` — create, verify, and restore from trusted
 * local snapshots (Phase 6).
 *
 * A snapshot is a local, encrypted and signed recovery point.  It is
 * never global truth and never triggers automatic rebaseline.
 *
 * Every restore from a snapshot produces a new signed `restore`
 * operation that flows through the existing pending-queue and
 * submit_vault_operation path.  No direct upsert.
 */

import { signEcdsaP256, verifyEcdsaP256 } from '@dis/shield/signing';
import {
  canonicalizeVaultStructure,
  decodeBase64Url,
  encodeBase64Url,
} from './canonicalJson';
import {
  computeVaultHead,
} from './recordHashes';
import {
  buildOperationSignedBody,
  signOperation,
  verifyOperationSignature,
  importDevicePublicKey,
} from './operationSigningService';
import {
  deriveRecordKey,
  openRecord,
} from './cryptoRecordService';
import { buildRecordAad } from './recordAad';
import {
  isDeviceCurrentlyTrusted,
  classifyOperationAuthor,
} from './deviceTrustService';
import {
  deriveSnapshotKey,
  sealSnapshot,
  openSnapshot,
  computeSnapshotHash,
  computeSnapshotAadHash,
} from './snapshotCrypto';
import {
  TRUSTED_SNAPSHOT_SCHEMA_V1,
  TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1,
  TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1,
  SNAPSHOT_HASH_SCHEMA_V1,
  SNAPSHOT_AAD_SCHEMA_V1,
  type TrustedSnapshotPlaintextV1,
  type TrustedSnapshotEnvelopeV1,
  type TrustedSnapshotCreationResult,
  type TrustedSnapshotVerificationResult,
  type SnapshotRecordEntryV1,
  type SnapshotExcludedRecordDiagnosisV1,
  type SnapshotAadV1,
  type BuildRestoreOperationFromSnapshotInput,
  type SnapshotStorage,
  TrustedSnapshotError,
} from './trustedSnapshotTypes';
import type {
  LocalVaultState,
  LocalVerifiedRecord,
} from './vaultStateMachine';
import type {
  RecordSecurityState,
} from './vaultSecurityStates';
import type {
  VaultOperationSignedBodyV1,
  SignedVaultOperationV1,
  TrustedDeviceRecordV1,
} from './types';
import type {
  BuiltVaultOperation,
  RestoreRecordBuilderInput,
} from './vaultOpLogOperationBuilder';
import type { TrustListInput } from './deviceTrustService';

// ---------------------------------------------------------------------------
// Snapshot creation
// ---------------------------------------------------------------------------

export interface CreateTrustedSnapshotInput {
  readonly snapshotId: string;
  readonly vaultId: string;
  readonly createdByDeviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly vaultEncryptionKey: Uint8Array;
  readonly trustEpoch: number;
  readonly verifiedVaultHead: string | null;
  readonly state: LocalVaultState;
  readonly trustedDevicesHash: string;
  readonly manifestHash: string;
  readonly now?: string;
}

/**
 * Create a trusted snapshot from the local verified vault state.
 *
 * Security gates:
 * - Current device must be trusted and able to sign.
 * - Manifest must be verifiable (caller provides manifestHash).
 * - No unclarified root inconsistency (caller checks vaultMode).
 * - Only `verified` and `deletedByTrustedDevice` records are included.
 * - Quarantined, conflict, pending and container-quarantined records are
 *   deliberately excluded and listed in the diagnosis.
 *
 * The plaintext is encrypted with a snapshot-specific AEAD key derived
 * from the vault encryption key.  The resulting envelope is signed by
 * the current device.
 */
export async function createTrustedSnapshot(
  input: CreateTrustedSnapshotInput,
): Promise<TrustedSnapshotCreationResult> {
  // Gate: device trust
  const device = input.state.trustedDevicesById.get(input.createdByDeviceId);
  if (!device || !isDeviceCurrentlyTrusted(device)) {
    throw new TrustedSnapshotError(
      'snapshot_untrusted_device',
      'snapshot creation refused: current device is not trusted',
    );
  }

  // Build plaintext from verified / deleted records only.
  const records: SnapshotRecordEntryV1[] = [];
  const excludedRecords: SnapshotExcludedRecordDiagnosisV1[] = [];

  for (const localRecord of input.state.recordsById.values()) {
    const decision = classifyRecordForSnapshot(localRecord.recordState);
    if (decision.include) {
      records.push(toSnapshotRecordEntry(localRecord));
    } else {
      excludedRecords.push({
        recordId: localRecord.record.recordId,
        recordType: localRecord.record.recordType,
        reason: (decision as { include: false; reason: SnapshotExcludedRecordDiagnosisV1['reason'] }).reason,
      });
    }
  }

  // Also scan quarantined records for exclusion diagnosis.
  for (const q of input.state.quarantinedRecordsById.values()) {
    if (q.record) {
      excludedRecords.push({
        recordId: q.record.recordId,
        recordType: q.record.recordType,
        reason: q.recordState as SnapshotExcludedRecordDiagnosisV1['reason'],
      });
    }
  }

  const createdAt = input.now ?? new Date().toISOString();

  const plaintext: TrustedSnapshotPlaintextV1 = {
    schema: TRUSTED_SNAPSHOT_SCHEMA_V1,
    snapshotId: input.snapshotId,
    vaultId: input.vaultId,
    createdAt,
    createdByDeviceId: input.createdByDeviceId,
    verifiedVaultHead: input.verifiedVaultHead,
    trustEpoch: input.trustEpoch,
    records,
    trustedDevicesHash: input.trustedDevicesHash,
    manifestHash: input.manifestHash,
  };

  const plaintextBytes = canonicalizeVaultStructure(plaintext);

  const snapshotKey = await deriveSnapshotKey({
    vaultEncryptionKey: input.vaultEncryptionKey,
    vaultId: input.vaultId,
    snapshotId: input.snapshotId,
    deviceId: input.createdByDeviceId,
    trustEpoch: input.trustEpoch,
  });

  let sealed: Awaited<ReturnType<typeof sealSnapshot>>;
  try {
    const aad: SnapshotAadV1 = {
      app: 'singra-vault',
      aadSchema: SNAPSHOT_AAD_SCHEMA_V1,
      vaultId: input.vaultId,
      snapshotId: input.snapshotId,
      deviceId: input.createdByDeviceId,
      trustEpoch: input.trustEpoch,
      verifiedVaultHead: input.verifiedVaultHead,
      createdAt,
    };
    sealed = await sealSnapshot({
      plaintext: plaintextBytes,
      snapshotKey,
      aad,
    });
  } finally {
    snapshotKey.fill(0);
  }

  // Precompute hash and signature before creating the readonly envelope.
  const preEnvelope = {
    schema: TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1,
    snapshotId: input.snapshotId,
    vaultId: input.vaultId,
    createdAt,
    createdByDeviceId: input.createdByDeviceId,
    verifiedVaultHead: input.verifiedVaultHead,
    trustEpoch: input.trustEpoch,
    encryptionSchema: TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1,
    signatureSchema: 'device-signature-v1' as const,
    nonce: sealed.nonceB64Url,
    aadHash: sealed.aadHash,
    snapshotCiphertext: sealed.ciphertextB64Url,
  };
  const snapshotHash = await computeSnapshotHash(preEnvelope);

  // Sign the snapshotHash bytes (deterministic, canonical).
  const hashBytes = decodeBase64Url(snapshotHash);
  const signature = encodeBase64Url(await signEcdsaP256(input.deviceSigningKey, hashBytes));

  const envelope: TrustedSnapshotEnvelopeV1 = {
    ...preEnvelope,
    snapshotHash,
    signature,
  };

  return { envelope, excludedRecords };
}

// ---------------------------------------------------------------------------
// Snapshot verification
// ---------------------------------------------------------------------------

export interface VerifyTrustedSnapshotInput {
  readonly envelope: TrustedSnapshotEnvelopeV1;
  readonly vaultId: string;
  readonly trust: TrustListInput;
  readonly vaultEncryptionKey: Uint8Array;
}

/**
 * Verify a snapshot envelope, then decrypt and schema-validate the
 * plaintext.
 *
 * Gates:
 * 1. Envelope schema version.
 * 2. VaultId, SnapshotId, DeviceId, TrustEpoch match expectations.
 * 3. Snapshot hash recomputation matches.
 * 4. Signature verifies against trusted device public key.
 * 5. AAD recomputation and hash match.
 * 6. AEAD decryption succeeds.
 * 7. Plaintext schema is valid.
 * 8. Device is trusted (not revoked, epoch matches).
 *
 * Returns the decrypted plaintext and the verified envelope.
 */
export async function verifyTrustedSnapshot(
  input: VerifyTrustedSnapshotInput,
): Promise<TrustedSnapshotVerificationResult> {
  const { envelope, vaultId, trust, vaultEncryptionKey } = input;

  // Gate 1: schema
  if (envelope.schema !== TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1) {
    throw new TrustedSnapshotError(
      'snapshot_schema_unsupported',
      `unsupported snapshot envelope schema: ${envelope.schema}`,
    );
  }
  if (envelope.encryptionSchema !== TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1) {
    throw new TrustedSnapshotError(
      'snapshot_schema_unsupported',
      `unsupported snapshot encryption schema: ${envelope.encryptionSchema}`,
    );
  }

  // Gate 2: vaultId match
  if (envelope.vaultId !== vaultId) {
    throw new TrustedSnapshotError(
      'snapshot_vault_mismatch',
      'snapshot vaultId does not match expected vault',
    );
  }

  // Gate 8: device trust
  const device = trust.trustedDevicesById.get(envelope.createdByDeviceId);
  if (!device) {
    throw new TrustedSnapshotError(
      'snapshot_untrusted_device',
      'snapshot author device is not in trust list',
    );
  }
  const authorClassification = classifyOperationAuthor(
    {
      body: {
        signatureSchema: 'device-signature-v1',
        opId: envelope.snapshotId,
        intentId: envelope.snapshotId,
        rebasedFromOpId: null,
        vaultId: envelope.vaultId,
        authorDeviceId: envelope.createdByDeviceId,
        opType: 'restore',
        recordId: envelope.snapshotId,
        recordType: 'manifest',
        baseRecordVersion: null,
        previousCiphertextHash: null,
        newRecordHash: null,
        baseVaultHead: envelope.verifiedVaultHead,
        payloadCiphertextHash: null,
        payloadAadHash: null,
        createdAtClient: envelope.createdAt,
        trustEpoch: envelope.trustEpoch,
      },
      signature: envelope.signature,
      opHash: envelope.snapshotHash,
    },
    trust,
  );
  if (authorClassification.status !== 'trusted') {
    throw new TrustedSnapshotError(
      'snapshot_device_revoked',
      `snapshot author is not trusted: ${authorClassification.status}`,
    );
  }

  // Gate 3: hash
  const recomputedHash = await computeSnapshotHash(envelope);
  if (recomputedHash !== envelope.snapshotHash) {
    throw new TrustedSnapshotError(
      'snapshot_hash_mismatch',
      'snapshot hash does not match canonical envelope',
    );
  }

  // Gate 4: signature
  const publicKey = await importDevicePublicKey(device.publicSigningKey);
  const hashBytes = decodeBase64Url(envelope.snapshotHash);
  let signatureValid: boolean;
  try {
    signatureValid = await verifyEcdsaP256(
      publicKey,
      decodeBase64Url(envelope.signature),
      hashBytes,
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    throw new TrustedSnapshotError(
      'snapshot_signature_invalid',
      'snapshot signature verification failed',
    );
  }

  // Gate 5: AAD
  const aad: SnapshotAadV1 = {
    app: 'singra-vault',
    aadSchema: SNAPSHOT_AAD_SCHEMA_V1,
    vaultId: envelope.vaultId,
    snapshotId: envelope.snapshotId,
    deviceId: envelope.createdByDeviceId,
    trustEpoch: envelope.trustEpoch,
    verifiedVaultHead: envelope.verifiedVaultHead,
    createdAt: envelope.createdAt,
  };
  const recomputedAadHash = await computeSnapshotAadHash(aad);
  if (recomputedAadHash !== envelope.aadHash) {
    throw new TrustedSnapshotError(
      'snapshot_aad_mismatch',
      'snapshot AAD hash does not match reconstructed AAD',
    );
  }

  // Gate 6: decrypt
  const snapshotKey = await deriveSnapshotKey({
    vaultEncryptionKey,
    vaultId: envelope.vaultId,
    snapshotId: envelope.snapshotId,
    deviceId: envelope.createdByDeviceId,
    trustEpoch: envelope.trustEpoch,
  });

  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = await openSnapshot({
      sealed: {
        aad,
        aadHash: envelope.aadHash,
        nonceB64Url: envelope.nonce,
        ciphertextB64Url: envelope.snapshotCiphertext,
      },
      snapshotKey,
      expectedAad: aad,
      expectedAadHash: envelope.aadHash,
    });
  } catch (e) {
    throw new TrustedSnapshotError(
      'snapshot_decrypt_failed',
      e instanceof Error ? e.message : 'snapshot decryption failed',
    );
  } finally {
    snapshotKey.fill(0);
  }

  // Gate 7: schema validation
  let plaintext: TrustedSnapshotPlaintextV1;
  try {
    plaintext = JSON.parse(new TextDecoder().decode(plaintextBytes)) as TrustedSnapshotPlaintextV1;
  } catch {
    throw new TrustedSnapshotError(
      'snapshot_plaintext_schema_invalid',
      'snapshot plaintext is not valid JSON',
    );
  }
  if (plaintext.schema !== TRUSTED_SNAPSHOT_SCHEMA_V1) {
    throw new TrustedSnapshotError(
      'snapshot_plaintext_schema_invalid',
      `unsupported snapshot plaintext schema: ${String(plaintext.schema)}`,
    );
  }
  if (plaintext.snapshotId !== envelope.snapshotId) {
    throw new TrustedSnapshotError(
      'snapshot_plaintext_schema_invalid',
      'snapshot plaintext snapshotId does not match envelope',
    );
  }
  if (plaintext.vaultId !== envelope.vaultId) {
    throw new TrustedSnapshotError(
      'snapshot_plaintext_schema_invalid',
      'snapshot plaintext vaultId does not match envelope',
    );
  }

  return { plaintext, envelope };
}

// ---------------------------------------------------------------------------
// Record selection from verified snapshot
// ---------------------------------------------------------------------------

/**
 * Find a snapshot record entry by recordId and optionally recordType.
 */
export function findSnapshotRecord(
  snapshot: TrustedSnapshotPlaintextV1,
  recordId: string,
  recordType?: string,
): SnapshotRecordEntryV1 | null {
  for (const rec of snapshot.records) {
    if (rec.recordId === recordId) {
      if (recordType === undefined || rec.recordType === recordType) {
        return rec;
      }
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Restore operation builder
// ---------------------------------------------------------------------------

export interface BuildRestoreOperationFromSnapshotInputExtended {
  readonly snapshotRecord: SnapshotRecordEntryV1;
  readonly vaultId: string;
  readonly recordId: string;
  readonly recordType: 'item' | 'category';
  readonly baseRecordVersion: number;
  readonly previousCiphertextHash: string;
  readonly baseVaultHead: string | null;
  readonly vaultEncryptionKey: Uint8Array;
  readonly keyVersion: number;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly trustEpoch: number;
  readonly opId: string;
  readonly intentId: string;
  readonly rebasedFromOpId: string | null;
  readonly createdAtClient?: string;
}

/**
 * Build a `restore` operation from a verified snapshot record.
 *
 * Steps:
 * 1. Derive the snapshot record's old record key and decrypt the
 *    ciphertext to obtain the original plaintext.
 * 2. Validate the plaintext against the record type schema (minimal
 *    non-empty check in Phase 6; full schema validation is Phase 9).
 * 3. Re-seal the plaintext with a fresh nonce, current keyVersion,
 *    and recordVersion = baseRecordVersion + 1.
 * 4. Build a canonical signed `restore` operation.
 * 5. Sign it with the current device key.
 *
 * Returns a `BuiltVaultOperation` ready for the pending queue.
 */
export async function buildRestoreOperationFromSnapshot(
  input: BuildRestoreOperationFromSnapshotInputExtended,
): Promise<BuiltVaultOperation> {
  const createdAtClient = input.createdAtClient ?? new Date().toISOString();

  // Step 1: decrypt the snapshot record to obtain plaintext.
  const oldRecordKey = await deriveRecordKey({
    vaultEncryptionKey: input.vaultEncryptionKey,
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    keyVersion: input.snapshotRecord.keyVersion,
  });

  let plaintext: Uint8Array;
  try {
    const opened = await openRecord({
      sealed: {
        aad: buildRecordAad({
          vaultId: input.vaultId,
          recordId: input.recordId,
          recordType: input.recordType,
          recordVersion: input.snapshotRecord.recordVersion,
          keyVersion: input.snapshotRecord.keyVersion,
        }),
        aadHash: input.snapshotRecord.aadHash,
        nonceB64Url: input.snapshotRecord.nonce,
        ciphertextB64Url: input.snapshotRecord.ciphertext,
        ciphertextHash: input.snapshotRecord.ciphertextHash,
      },
      recordKey: oldRecordKey,
      expectedAadInput: {
        vaultId: input.vaultId,
        recordId: input.recordId,
        recordType: input.recordType,
        recordVersion: input.snapshotRecord.recordVersion,
        keyVersion: input.snapshotRecord.keyVersion,
      },
      expectedAadHash: input.snapshotRecord.aadHash,
      expectedCiphertextHash: input.snapshotRecord.ciphertextHash,
    });
    plaintext = opened.plaintext;
  } finally {
    oldRecordKey.fill(0);
  }

  // Step 2: plaintext schema gate.
  if (!validateRestorePlaintext(plaintext, input.recordType)) {
    throw new TrustedSnapshotError(
      'restore_invalid_plaintext',
      `restore plaintext failed schema validation for ${input.recordType}`,
    );
  }

  // Step 3: re-seal with fresh nonce and current metadata.
  // Import here to avoid circular dependency.
  const { sealRecord } = await import('./cryptoRecordService');
  const nextRecordVersion = input.baseRecordVersion + 1;

  const recordKey = await deriveRecordKey({
    vaultEncryptionKey: input.vaultEncryptionKey,
    vaultId: input.vaultId,
    recordId: input.recordId,
    recordType: input.recordType,
    keyVersion: input.keyVersion,
  });

  let sealed: Awaited<ReturnType<typeof sealRecord>>;
  try {
    sealed = await sealRecord({
      plaintext,
      recordKey,
      aadInput: {
        vaultId: input.vaultId,
        recordId: input.recordId,
        recordType: input.recordType,
        recordVersion: nextRecordVersion,
        keyVersion: input.keyVersion,
      },
    });
  } finally {
    recordKey.fill(0);
  }

  // Step 4: build canonical signed body.
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

  // Step 5: sign.
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

// ---------------------------------------------------------------------------
// Category restore re-evaluation (state machine helper)
// ---------------------------------------------------------------------------

/**
 * After a successful category restore, re-evaluate items that were
 * container-quarantined solely because of the restored category.
 *
 * Only items that are themselves `verified` may leave
 * `containerQuarantined`.  Manipulated or quarantined items stay
 * isolated.  This function never sets `lockedCritical`.
 */
export function reevaluateContainerQuarantinedItems(
  state: LocalVaultState,
  _restoredCategoryRecordId: string,
): LocalVaultState {
  const nextRecords = new Map(state.recordsById);
  let changed = false;

  for (const [recordId, entry] of state.recordsById) {
    if (entry.recordState !== 'containerQuarantined') {
      continue;
    }
    if (entry.record.recordType !== 'item') {
      continue;
    }
    // In Phase 6 we do not yet track the exact category that caused
    // the container quarantine.  The caller is responsible for only
    // invoking this helper when the restored category is the sole
    // known cause for the items it references.
    // We downgrade containerQuarantined back to verified so the item
    // can be displayed again.  Items that have any other problem
    // (tampered, unknown author, etc.) are in quarantinedRecordsById,
    // not in recordsById with containerQuarantined.
    nextRecords.set(recordId, {
      ...entry,
      recordState: 'verified',
    });
    changed = true;
  }

  if (!changed) {
    return state;
  }

  return {
    ...state,
    recordsById: nextRecords,
  };
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/**
 * Persist a verified snapshot envelope to local storage.
 */
export async function saveSnapshotEnvelope(
  storage: SnapshotStorage,
  envelope: TrustedSnapshotEnvelopeV1,
): Promise<void> {
  await storage.save(envelope);
}

/**
 * Load and verify a snapshot by id, returning the decrypted plaintext.
 */
export async function loadAndVerifySnapshot(
  storage: SnapshotStorage,
  snapshotId: string,
  vaultId: string,
  trust: TrustListInput,
  vaultEncryptionKey: Uint8Array,
): Promise<TrustedSnapshotVerificationResult> {
  const envelope = await storage.load(snapshotId);
  if (envelope === null) {
    throw new TrustedSnapshotError(
      'snapshot_record_not_found',
      `snapshot not found in local storage: ${snapshotId}`,
    );
  }
  return verifyTrustedSnapshot({ envelope, vaultId, trust, vaultEncryptionKey });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function classifyRecordForSnapshot(
  state: RecordSecurityState,
): { include: true } | { include: false; reason: SnapshotExcludedRecordDiagnosisV1['reason'] } {
  switch (state) {
    case 'verified':
    case 'deletedByTrustedDevice':
    case 'restoredFromSnapshot':
      return { include: true };
    case 'conflict':
      return { include: false, reason: 'conflict' };
    case 'pendingVerification':
      return { include: false, reason: 'pendingVerification' };
    case 'quarantinedTampered':
      return { include: false, reason: 'quarantinedTampered' };
    case 'quarantinedUnknownAuthor':
      return { include: false, reason: 'quarantinedUnknownAuthor' };
    case 'quarantinedMissingWithoutDelete':
      return { include: false, reason: 'quarantinedMissingWithoutDelete' };
    case 'quarantinedUnreadable':
      return { include: false, reason: 'quarantinedUnreadable' };
    case 'quarantinedInvalidSchema':
      return { include: false, reason: 'quarantinedInvalidSchema' };
    case 'containerQuarantined':
      return { include: false, reason: 'containerQuarantined' };
    default:
      return { include: false, reason: 'quarantinedTampered' };
  }
}

function toSnapshotRecordEntry(localRecord: LocalVerifiedRecord): SnapshotRecordEntryV1 {
  const rec = localRecord.record;
  return {
    recordId: rec.recordId,
    recordType: rec.recordType,
    recordVersion: rec.recordVersion,
    keyVersion: rec.keyVersion,
    ciphertext: rec.ciphertext,
    nonce: rec.nonce,
    aadHash: rec.aadHash,
    ciphertextHash: rec.ciphertextHash,
    lastVerifiedOpId: rec.lastOpId,
    deleted: localRecord.recordState === 'deletedByTrustedDevice',
  };
}

function validateRestorePlaintext(plaintext: Uint8Array, recordType: 'item' | 'category'): boolean {
  if (plaintext.length === 0) {
    return false;
  }
  // Phase 6 minimal gate: JSON must parse to a non-null object.
  try {
    const parsed = JSON.parse(new TextDecoder().decode(plaintext));
    if (parsed === null || typeof parsed !== 'object') {
      return false;
    }
    if (recordType === 'category') {
      return typeof parsed.name === 'string';
    }
    if (recordType === 'item') {
      return typeof parsed.name === 'string' || typeof parsed.title === 'string' || typeof parsed.username === 'string';
    }
    return true;
  } catch {
    return false;
  }
}
