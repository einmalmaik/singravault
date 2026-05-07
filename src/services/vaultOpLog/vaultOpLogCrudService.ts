// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Phase 12 CRUD orchestrator for item/category mutations through the
 * signed vault operation log.
 *
 * This module does not implement crypto primitives. It composes the
 * existing operation builder, pending queue, repository RPC, and
 * state-machine reload path.
 */

import { canonicalizeVaultStructure } from './canonicalJson';
import {
  buildCreateRecordOperation,
  buildDeleteRecordOperation,
  buildRestoreRecordOperation,
  buildUpdateRecordOperation,
  toVaultOperationRow,
  type BuiltVaultOperation,
} from './vaultOpLogOperationBuilder';
import {
  VaultOpLogPendingQueue,
  classifySubmitResult,
} from './vaultOpLogPendingQueue';
import type { QueuePersistence } from './vaultOpLogPendingQueueTypes';
import { LocalStorageQueuePersistence } from './vaultOpLogQueuePersistence';
import {
  submitVaultOperation,
  type SupabaseRpcClient,
} from './vaultOpLogRepository';
import {
  loadVaultOpLogUiState,
  type VaultOpLogTrustReadClient,
} from './vaultOpLogUiOrchestrator';
import type { LocalVerifiedRecord } from './vaultStateMachine';
import type { RecordType } from './types';
import type { VaultOperationRow } from './vaultOpLogRpcTypes';

export class VaultOpLogCrudServiceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultOpLogCrudServiceError';
  }
}

export class MissingVerifiedVaultHeadError extends VaultOpLogCrudServiceError {
  constructor() {
    super('Der verifizierte Vault-Head fehlt. Die Operation wird fail-closed blockiert.');
  }
}

export class MissingVerifiedBaseMetadataError extends VaultOpLogCrudServiceError {
  constructor() {
    super('Verifizierte Basis-Metadaten fehlen. Die Operation wird fail-closed blockiert.');
  }
}

export class CategoryStillReferencedError extends VaultOpLogCrudServiceError {
  constructor(recordId: string, count: number) {
    super(`Kategorie ${recordId} wird noch von ${count} Eintrag(en) referenziert.`);
  }
}

export class OperationSubmissionFailedError extends VaultOpLogCrudServiceError {
  constructor(public readonly reason: string) {
    super(`Operation konnte nicht übermittelt werden: ${reason}`);
  }
}

export class OperationSubmissionRetryableError extends VaultOpLogCrudServiceError {
  constructor(public readonly reason: string) {
    super(`Operation bleibt in der Pending Queue: ${reason}`);
  }
}

export class OperationVerificationAfterCommitError extends VaultOpLogCrudServiceError {
  constructor(public readonly reason: string) {
    super(`Operation wurde übertragen, aber nicht lokal verifiziert: ${reason}`);
  }
}

export class RebaseRequiredError extends VaultOpLogCrudServiceError {
  constructor() {
    super('Die Operation basiert auf einem veralteten Vault-Head. Rebase erforderlich.');
  }
}

export class RecordConflictError extends VaultOpLogCrudServiceError {
  constructor() {
    super('Ein gleichzeitiger Record-Konflikt wurde erkannt.');
  }
}

export interface VaultOpLogCrudServiceDependencies {
  readonly vaultId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly vaultEncryptionKey: Uint8Array;
  readonly publicSigningKeyB64Url: string;
  readonly trustEpoch: number;
  readonly keyVersion: number;
  readonly rpcClient: SupabaseRpcClient;
  readonly trustClient?: VaultOpLogTrustReadClient;
  readonly queuePersistence?: QueuePersistence;
}

export interface VerifiedVaultBase {
  readonly baseVaultHead: string | null;
}

export interface VerifiedRecordBase {
  readonly recordVersion: number;
  readonly ciphertextHash: string;
  readonly baseVaultHead: string;
}

export interface SubmissionPipelineResult {
  readonly resultingVaultHead: string;
}

export interface ItemPlaintext {
  readonly title: string;
  readonly websiteUrl?: string | null;
  readonly username?: string | null;
  readonly password?: string | null;
  readonly notes?: string | null;
  readonly itemType: 'password' | 'note' | 'totp' | 'card';
  readonly categoryRecordId?: string | null;
  readonly isFavorite?: boolean;
  readonly sortOrder?: number | null;
  readonly totpSecret?: string | null;
  readonly totpIssuer?: string | null;
  readonly totpLabel?: string | null;
  readonly totpAlgorithm?: 'SHA1' | 'SHA256' | 'SHA512' | null;
  readonly totpDigits?: 6 | 8 | null;
  readonly totpPeriod?: number | null;
  readonly customFields?: Record<string, string> | null;
}

export interface CategoryPlaintext {
  readonly name: string;
  readonly icon?: string | null;
  readonly color?: string | null;
  readonly parentCategoryRecordId?: string | null;
  readonly sortOrder?: number | null;
}

type ExpectedVerificationState = 'active' | 'deleted';

function encodePlaintext(payload: Record<string, unknown>): Uint8Array {
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value !== undefined) {
      cleaned[key] = value;
    }
  }
  return canonicalizeVaultStructure(cleaned);
}

function encodeItemPlaintext(data: ItemPlaintext): Uint8Array {
  return encodePlaintext({
    title: data.title,
    websiteUrl: data.websiteUrl,
    username: data.username,
    password: data.password,
    notes: data.notes,
    itemType: data.itemType,
    categoryRecordId: data.categoryRecordId ?? null,
    isFavorite: data.isFavorite,
    sortOrder: data.sortOrder,
    totpSecret: data.totpSecret,
    totpIssuer: data.totpIssuer,
    totpLabel: data.totpLabel,
    totpAlgorithm: data.totpAlgorithm,
    totpDigits: data.totpDigits,
    totpPeriod: data.totpPeriod,
    customFields: data.customFields,
  });
}

function encodeCategoryPlaintext(data: CategoryPlaintext): Uint8Array {
  return encodePlaintext({
    name: data.name,
    icon: data.icon,
    color: data.color,
    parentCategoryRecordId: data.parentCategoryRecordId ?? null,
    sortOrder: data.sortOrder,
  });
}

export function requireVerifiedVaultBase(base: VerifiedVaultBase | null): VerifiedVaultBase {
  if (!base) {
    throw new MissingVerifiedVaultHeadError();
  }
  return base;
}

export function requireVerifiedBaseMetadata(base: VerifiedRecordBase | null): VerifiedRecordBase {
  if (!base || !base.baseVaultHead) {
    throw new MissingVerifiedBaseMetadataError();
  }
  return base;
}

export function getVerifiedRecordBase(
  record: LocalVerifiedRecord | null,
  baseVaultHead: string | null,
): VerifiedRecordBase {
  if (
    !record
    || (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
    || !baseVaultHead
  ) {
    throw new MissingVerifiedBaseMetadataError();
  }

  return {
    recordVersion: record.record.recordVersion,
    ciphertextHash: record.record.ciphertextHash,
    baseVaultHead,
  };
}

function recordPayloadFromBuilt(built: BuiltVaultOperation): {
  readonly aadHash: string;
  readonly ciphertextHash: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly keyVersion: number;
} {
  return {
    aadHash: built.sealedRecord.aadHash,
    ciphertextHash: built.sealedRecord.ciphertextHash,
    nonce: built.sealedRecord.nonceB64Url,
    ciphertext: built.sealedRecord.ciphertextB64Url,
    keyVersion: built.sealedRecord.aad.keyVersion,
  };
}

async function submitAndVerify(
  deps: VaultOpLogCrudServiceDependencies,
  built: BuiltVaultOperation,
  expectedState: ExpectedVerificationState,
): Promise<SubmissionPipelineResult> {
  const opRow: VaultOperationRow = toVaultOperationRow(built);
  const queue = new VaultOpLogPendingQueue(
    deps.vaultId,
    deps.queuePersistence ?? new LocalStorageQueuePersistence(),
  );

  await queue.load();
  await queue.recoverAfterCrash();
  await queue.enqueue(built);
  await queue.markSyncing(opRow.opId);

  let classified: ReturnType<typeof classifySubmitResult>;
  try {
    classified = classifySubmitResult(await submitVaultOperation(
      deps.rpcClient,
      opRow,
      recordPayloadFromBuilt(built),
      null,
    ));
  } catch {
    await queue.markRetryable(opRow.opId, 'submit_vault_operation threw');
    throw new OperationSubmissionRetryableError('submit_vault_operation threw');
  }

  switch (classified.kind) {
    case 'synced':
    case 'idempotentSynced': {
      await queue.markSynced(opRow.opId, classified.resultingVaultHead);
      await verifyCommittedOperation(deps, opRow, expectedState);
      return { resultingVaultHead: classified.resultingVaultHead };
    }
    case 'retryable':
      await queue.markRetryable(opRow.opId, classified.error);
      throw new OperationSubmissionRetryableError(classified.error);
    case 'rebaseNeeded':
      await queue.markRebaseNeeded(opRow.opId);
      throw new RebaseRequiredError();
    case 'recordConflict':
      await queue.markConflict(opRow.opId, 'record_conflict');
      throw new RecordConflictError();
    case 'permanentFailed':
      await queue.markFailed(opRow.opId, classified.error);
      throw new OperationSubmissionFailedError(classified.error);
    default:
      await queue.markFailed(opRow.opId, 'unexpected_submit_classification');
      throw new OperationSubmissionFailedError('unexpected_submit_classification');
  }
}

async function verifyCommittedOperation(
  deps: VaultOpLogCrudServiceDependencies,
  operation: VaultOperationRow,
  expectedState: ExpectedVerificationState,
): Promise<void> {
  const verification = await loadVaultOpLogUiState({
    rpcClient: deps.rpcClient,
    trustClient: deps.trustClient,
    vaultId: deps.vaultId,
    deviceId: deps.deviceId,
    publicSigningKeyB64Url: deps.publicSigningKeyB64Url,
    vaultEncryptionKey: deps.vaultEncryptionKey,
  });

  if (verification.error || !verification.localVaultState) {
    throw new OperationVerificationAfterCommitError(
      verification.error ?? 'state_machine_reload_failed',
    );
  }

  const verifiedRecord = verification.localVaultState.recordsById.get(operation.recordId);
  if (!verifiedRecord) {
    const quarantinedRecord = verification.localVaultState.quarantinedRecordsById.get(operation.recordId);
    if (quarantinedRecord) {
      throw new OperationVerificationAfterCommitError(
        `submitted_record_quarantined_after_reload:${quarantinedRecord.reason}`,
      );
    }
    throw new OperationVerificationAfterCommitError('submitted_record_missing_after_reload');
  }

  if (expectedState === 'deleted') {
    if (verifiedRecord.recordState !== 'deletedByTrustedDevice') {
      throw new OperationVerificationAfterCommitError('delete_not_verified_as_tombstone');
    }
    return;
  }

  if (verifiedRecord.recordState !== 'verified' && verifiedRecord.recordState !== 'restoredFromSnapshot') {
    throw new OperationVerificationAfterCommitError(`record_not_verified_after_reload:${verifiedRecord.recordState}`);
  }
}

export async function createItem(
  deps: VaultOpLogCrudServiceDependencies,
  base: VerifiedVaultBase | null,
  plaintext: ItemPlaintext,
): Promise<SubmissionPipelineResult & { recordId: string }> {
  const verifiedBase = requireVerifiedVaultBase(base);
  const recordId = crypto.randomUUID();
  const built = await buildCreateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'item',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: encodeItemPlaintext(plaintext),
    keyVersion: deps.keyVersion,
  });

  const result = await submitAndVerify(deps, built, 'active');
  return { ...result, recordId };
}

export async function updateItem(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  base: VerifiedRecordBase | null,
  plaintext: ItemPlaintext,
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  const built = await buildUpdateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'item',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: encodeItemPlaintext(plaintext),
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'active');
}

export async function deleteItem(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  base: VerifiedRecordBase | null,
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  const built = await buildDeleteRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'item',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'deleted');
}

export async function createCategory(
  deps: VaultOpLogCrudServiceDependencies,
  base: VerifiedVaultBase | null,
  plaintext: CategoryPlaintext,
): Promise<SubmissionPipelineResult & { recordId: string }> {
  const verifiedBase = requireVerifiedVaultBase(base);
  const recordId = crypto.randomUUID();
  const built = await buildCreateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'category',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: encodeCategoryPlaintext(plaintext),
    keyVersion: deps.keyVersion,
  });

  const result = await submitAndVerify(deps, built, 'active');
  return { ...result, recordId };
}

export async function updateCategory(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  base: VerifiedRecordBase | null,
  plaintext: CategoryPlaintext,
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  const built = await buildUpdateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'category',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: encodeCategoryPlaintext(plaintext),
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'active');
}

export async function deleteCategory(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  base: VerifiedRecordBase | null,
  referencedItemRecordIds: readonly string[],
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  if (referencedItemRecordIds.length > 0) {
    throw new CategoryStillReferencedError(recordId, referencedItemRecordIds.length);
  }

  const built = await buildDeleteRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType: 'category',
    vaultEncryptionKey: deps.vaultEncryptionKey,
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'deleted');
}

export async function restoreRecord(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  recordType: Extract<RecordType, 'item' | 'category'>,
  base: VerifiedRecordBase | null,
  verifiedSnapshotPlaintext: Uint8Array,
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  const built = await buildRestoreRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType,
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: verifiedSnapshotPlaintext,
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'active');
}

export async function resolveConflict(
  deps: VaultOpLogCrudServiceDependencies,
  recordId: string,
  recordType: Extract<RecordType, 'item' | 'category'>,
  base: VerifiedRecordBase | null,
  resolvedPlaintext: Uint8Array,
): Promise<SubmissionPipelineResult> {
  const verifiedBase = requireVerifiedBaseMetadata(base);
  const built = await buildUpdateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: deps.vaultId,
    recordId,
    deviceId: deps.deviceId,
    deviceSigningKey: deps.deviceSigningKey,
    trustEpoch: deps.trustEpoch,
    baseVaultHead: verifiedBase.baseVaultHead,
    recordType,
    vaultEncryptionKey: deps.vaultEncryptionKey,
    plaintext: resolvedPlaintext,
    keyVersion: deps.keyVersion,
    baseRecordVersion: verifiedBase.recordVersion,
    previousCiphertextHash: verifiedBase.ciphertextHash,
  });

  return submitAndVerify(deps, built, 'active');
}
