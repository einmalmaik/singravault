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
