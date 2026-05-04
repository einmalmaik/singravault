// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Public surface of the operation-log-based vault integrity layer
 * (phase 1). Re-exports only the documented contracts. Internal
 * helpers stay module-private.
 */

export {
  canonicalizeVaultStructure,
  canonicalizeVaultStructureAsString,
  encodeBase64Url,
  decodeBase64Url,
  constantTimeEquals,
  isUint8ArrayLike,
} from './canonicalJson';

export {
  buildRecordAad,
  encodeRecordAadBytes,
  recordAadsEqual,
} from './recordAad';

export {
  computeAadHash,
  computeCiphertextHash,
  computeOpHash,
  computeVaultHead,
  sha256Base64Url,
} from './recordHashes';

export {
  deriveRecordKey,
  sealRecord,
  openRecord,
} from './cryptoRecordService';

export {
  generateDeviceSigningKeyPair,
  importDevicePublicKey,
  buildOperationSignedBody,
  signOperation,
  verifyOperationSignature,
  type BuildOperationBodyInput,
  type DeviceSigningKeyPair,
} from './operationSigningService';

export {
  classifyOperationAuthor,
  applyDeviceTrustOperation,
  isDeviceCurrentlyTrusted,
  type DeviceTrustOperationPayload,
  type TrustListInput,
} from './deviceTrustService';

export {
  APP_NAMESPACE,
  DEVICE_SIGNATURE_SCHEMA_V1,
  OPERATION_TYPES,
  RECORD_AAD_SCHEMA_V1,
  RECORD_ENCRYPTION_SCHEMA_V1,
  RECORD_TYPES,
  VaultCanonicalizationError,
  VaultCryptoError,
  VaultSignatureError,
  isOperationType,
  isRecordType,
  type AuthorTrustClassification,
  type BuildRecordAadInput,
  type DerivedRecordKeyV1,
  type OpenedRecordV1,
  type OperationType,
  type RecordAadV1,
  type RecordType,
  type SealedRecordV1,
  type SignedVaultOperationV1,
  type TrustedDeviceRecordV1,
  type VaultCanonicalizationErrorCode,
  type VaultCryptoErrorCode,
  type VaultOperationSignedBodyV1,
  type VaultSignatureErrorCode,
} from './types';

// ---------------------------------------------------------------------------
// Phase 3 — Repository layer and feature flag (isolated, gated)
// ---------------------------------------------------------------------------

export { isVaultOpLogRepositoryEnabled } from './vaultOpLogFeatureFlags';

export {
  VaultOpLogMapperError,
  mapDbOperationRowToDomain,
  mapDbRecordRowToDomain,
  mapDbHeadRowToDomain,
  buildSubmitVaultOperationRequest,
  buildGetVaultHeadRequest,
  buildGetVaultChangesSinceRequest,
  buildGetVaultRecordsByIdsRequest,
  buildBootstrapVaultTrustRequest,
} from './vaultOpLogMappers';

export {
  submitVaultOperation,
  getVaultHead,
  getVaultChangesSince,
  getVaultRecordsByIds,
  bootstrapVaultTrust,
} from './vaultOpLogRepository';

export type {
  BootstrapVaultTrustResult,
  DbVaultHeadRow,
  DbVaultOperationRow,
  DbVaultRecordRow,
  GetVaultChangesSinceResult,
  GetVaultHeadResult,
  GetVaultRecordsByIdsResult,
  RpcBootstrapVaultTrustRequest,
  RpcGetVaultChangesSinceRequest,
  RpcGetVaultHeadRequest,
  RpcGetVaultRecordsByIdsRequest,
  RpcSubmitVaultOperationRequest,
  SubmitVaultOperationResult,
  VaultHeadRow,
  VaultOperationRow,
  VaultRecordRow,
} from './vaultOpLogRpcTypes';

// ---------------------------------------------------------------------------
// Phase 4 — Local pending queue, operation builder, retry and rebase
// ---------------------------------------------------------------------------

export {
  buildCreateRecordOperation,
  buildUpdateRecordOperation,
  buildDeleteRecordOperation,
  buildRestoreRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
  VaultOperationBuilderError,
  type BaseOperationBuilderInput,
  type BuiltVaultOperation,
  type CreateRecordBuilderInput,
  type DeleteRecordBuilderInput,
  type UpdateRecordBuilderInput,
} from './vaultOpLogOperationBuilder';

export {
  VaultOpLogPendingQueue,
  classifySubmitResult,
  sanitizeQueueErrorForStorage,
} from './vaultOpLogPendingQueue';

export {
  InMemoryQueuePersistence,
  LocalStorageQueuePersistence,
} from './vaultOpLogQueuePersistence';

export {
  InMemoryQueueLock,
  LocalStorageLeaderQueueLock,
  WebLocksQueueLock,
  type QueueLock,
} from './vaultOpLogQueueLock';

export {
  rebaseOperationWithPlaintext,
  type RebaseContext,
  type RebaseResult,
} from './vaultOpLogRebaseService';

export type {
  ClassifiedSubmitResult,
  PendingLocalOperation,
  PendingOperationState,
  QueuePersistence,
} from './vaultOpLogPendingQueueTypes';

// ---------------------------------------------------------------------------
// Phase 5 — Vault state machine and verification pipeline
// ---------------------------------------------------------------------------

export {
  canDecryptVerifiedRecordContext,
  type RecordSecurityState,
  type VaultSecurityMode,
  type OperationVerificationResult,
  type RecordContextVerificationResult,
} from './vaultSecurityStates';

export {
  verifyOperation,
  type VerifyOperationInput,
} from './verifyOperation';

export {
  verifyRecordContext,
  type VerifyRecordContextInput,
} from './verifyRecordContext';

export {
  applyRemoteOperation,
  applyTrustedDelete,
  determineVaultSecurityMode,
  type LocalVaultState,
  type LocalVerifiedRecord,
  type LocalQuarantinedRecord,
  type LocalRecordConflict,
  type ApplyRemoteOperationInput,
  type ApplyRemoteOperationResult,
  type ApplyTrustedDeleteInput,
  type ApplyTrustedDeleteResult,
} from './vaultStateMachine';

// ---------------------------------------------------------------------------
// Phase 6 — Trusted snapshots and recovery operations
// ---------------------------------------------------------------------------

export {
  createTrustedSnapshot,
  verifyTrustedSnapshot,
  findSnapshotRecord,
  buildRestoreOperationFromSnapshot,
  reevaluateContainerQuarantinedItems,
  saveSnapshotEnvelope,
  loadAndVerifySnapshot,
  type CreateTrustedSnapshotInput,
  type VerifyTrustedSnapshotInput,
  type BuildRestoreOperationFromSnapshotInputExtended,
} from './trustedSnapshotService';

export {
  applySnapshotRetentionPolicy,
  type RetentionDiagnosis,
} from './snapshotRetentionPolicy';

export {
  deriveSnapshotKey,
  sealSnapshot,
  openSnapshot,
  computeSnapshotHash,
  computeSnapshotAadHash,
  type SealSnapshotInput,
  type SealedSnapshotV1,
  type OpenSnapshotInput,
} from './snapshotCrypto';

export {
  TRUSTED_SNAPSHOT_SCHEMA_V1,
  TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1,
  TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1,
  SNAPSHOT_HASH_SCHEMA_V1,
  SNAPSHOT_AAD_SCHEMA_V1,
  TrustedSnapshotError,
  type TrustedSnapshotPlaintextV1,
  type TrustedSnapshotEnvelopeV1,
  type TrustedSnapshotCreationResult,
  type TrustedSnapshotVerificationResult,
  type SnapshotRecordEntryV1,
  type SnapshotExcludedRecordDiagnosisV1,
  type SnapshotAadV1,
  type BuildRestoreOperationFromSnapshotInput,
  type SnapshotStorage,
} from './trustedSnapshotTypes';
