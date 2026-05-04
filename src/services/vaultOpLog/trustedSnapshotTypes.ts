// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Versioned types for trusted snapshot plaintext, envelope and AAD.
 *
 * A snapshot is a local, encrypted and signed recovery point.  It is
 * never global truth and never triggers automatic rebaseline.
 */

export const TRUSTED_SNAPSHOT_SCHEMA_V1 = 'trusted-snapshot-v1' as const;
export const TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1 = 'trusted-snapshot-envelope-v1' as const;
export const TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1 = 'trusted-snapshot-aead-v1' as const;
export const SNAPSHOT_KEY_DERIVATION_PURPOSE = 'singra-vault/snapshot-key-v1' as const;
export const SNAPSHOT_HASH_SCHEMA_V1 = 'snapshot-hash-v1' as const;
export const SNAPSHOT_AAD_SCHEMA_V1 = 'snapshot-aad-v1' as const;

/**
 * A single record entry inside a snapshot plaintext.
 * Only verified or deleted-by-trusted-device records are stored.
 */
export interface SnapshotRecordEntryV1 {
  readonly recordId: string;
  readonly recordType: string;
  readonly recordVersion: number;
  readonly keyVersion: number;
  readonly ciphertext: string;
  readonly nonce: string;
  readonly aadHash: string;
  readonly ciphertextHash: string;
  readonly lastVerifiedOpId: string;
  readonly deleted: boolean;
}

/**
 * The decrypted content of a trusted snapshot.
 */
export interface TrustedSnapshotPlaintextV1 {
  readonly schema: typeof TRUSTED_SNAPSHOT_SCHEMA_V1;
  readonly snapshotId: string;
  readonly vaultId: string;
  readonly createdAt: string;
  readonly createdByDeviceId: string;
  readonly verifiedVaultHead: string | null;
  readonly trustEpoch: number;
  readonly records: readonly SnapshotRecordEntryV1[];
  readonly trustedDevicesHash: string;
  readonly manifestHash: string;
}

/**
 * The canonical AAD bound to a snapshot envelope.
 */
export interface SnapshotAadV1 {
  readonly app: 'singra-vault';
  readonly aadSchema: typeof SNAPSHOT_AAD_SCHEMA_V1;
  readonly vaultId: string;
  readonly snapshotId: string;
  readonly deviceId: string;
  readonly trustEpoch: number;
  readonly verifiedVaultHead: string | null;
  readonly createdAt: string;
}

/**
 * The encrypted, signed envelope that is persisted locally.
 */
export interface TrustedSnapshotEnvelopeV1 {
  readonly schema: typeof TRUSTED_SNAPSHOT_ENVELOPE_SCHEMA_V1;
  readonly snapshotId: string;
  readonly vaultId: string;
  readonly createdAt: string;
  readonly createdByDeviceId: string;
  readonly verifiedVaultHead: string | null;
  readonly trustEpoch: number;
  readonly encryptionSchema: typeof TRUSTED_SNAPSHOT_AEAD_SCHEMA_V1;
  readonly signatureSchema: 'device-signature-v1';
  readonly nonce: string;
  readonly aadHash: string;
  readonly snapshotCiphertext: string;
  readonly snapshotHash: string;
  readonly signature: string;
}

/**
 * Diagnose entry for records that were deliberately excluded from a
 * snapshot, without storing any plaintext.
 */
export interface SnapshotExcludedRecordDiagnosisV1 {
  readonly recordId: string;
  readonly recordType: string;
  readonly reason:
    | 'quarantinedTampered'
    | 'quarantinedUnknownAuthor'
    | 'quarantinedMissingWithoutDelete'
    | 'quarantinedUnreadable'
    | 'quarantinedInvalidSchema'
    | 'pendingVerification'
    | 'conflict'
    | 'containerQuarantined';
}

/**
 * Full snapshot creation output, including the encrypted envelope and
 * optional exclusion list for auditability.
 */
export interface TrustedSnapshotCreationResult {
  readonly envelope: TrustedSnapshotEnvelopeV1;
  readonly excludedRecords: readonly SnapshotExcludedRecordDiagnosisV1[];
}

/**
 * Result of verifying and decrypting a snapshot envelope.
 */
export interface TrustedSnapshotVerificationResult {
  readonly plaintext: TrustedSnapshotPlaintextV1;
  readonly envelope: TrustedSnapshotEnvelopeV1;
}

/**
 * Inputs for building a restore operation from a snapshot record.
 */
export interface BuildRestoreOperationFromSnapshotInput {
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
}

/**
 * Minimal storage interface for snapshot envelopes.  Callers provide
 * the adapter (IndexedDB, Tauri, etc.).
 */
export interface SnapshotStorage {
  save(envelope: TrustedSnapshotEnvelopeV1): Promise<void>;
  load(snapshotId: string): Promise<TrustedSnapshotEnvelopeV1 | null>;
  listForVault(vaultId: string): Promise<readonly TrustedSnapshotEnvelopeV1[]>;
  delete(snapshotId: string): Promise<void>;
}

/**
 * Service-level error for snapshot operations.
 */
export class TrustedSnapshotError extends Error {
  public readonly code:
    | 'snapshot_untrusted_device'
    | 'snapshot_manifest_unverified'
    | 'snapshot_root_inconsistency'
    | 'snapshot_contains_quarantined'
    | 'snapshot_schema_unsupported'
    | 'snapshot_aad_mismatch'
    | 'snapshot_hash_mismatch'
    | 'snapshot_signature_invalid'
    | 'snapshot_decrypt_failed'
    | 'snapshot_record_not_found'
    | 'snapshot_plaintext_schema_invalid'
    | 'snapshot_device_revoked'
    | 'snapshot_vault_mismatch'
    | 'snapshot_retention_fatal'
    | 'restore_invalid_plaintext';

  constructor(
    code: TrustedSnapshotError['code'],
    message?: string,
  ) {
    super(message ?? code);
    this.code = code;
    this.name = 'TrustedSnapshotError';
  }
}
