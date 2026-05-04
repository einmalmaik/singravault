// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Types for Phase 8 — Shadow Mode parallel verification.
 *
 * All fields are designed to contain only non-secret metadata:
 * counts, status codes, hash prefixes, record IDs, and classification
 * reasons. No plaintext vault data, no passwords, no usernames,
 * no URLs, no notes, no ciphertexts, no keys, no tokens.
 */

export type ShadowModeRunStatus =
  | 'notStarted'
  | 'inProgress'
  | 'completed'
  | 'failed'
  | 'skippedFlagDisabled';

export type ShadowModeRecordClassification =
  | 'verified'
  | 'quarantined'
  | 'conflict'
  | 'deleted'
  | 'pending'
  | 'unreadable';

export interface ShadowModeRecordDiagnosis {
  readonly recordId: string;
  readonly recordType: string;
  readonly recordVersion: number;
  readonly classification: ShadowModeRecordClassification;
  /** Short, fixed reason code; never contains user data. */
  readonly reasonCode: string;
  /** First 8 chars of the ciphertext hash for correlation. */
  readonly hashPrefix: string;
}

export interface ShadowModeVaultDiagnosis {
  readonly vaultId: string;
  readonly runAt: string;
  readonly status: ShadowModeRunStatus;
  readonly errorKind: ShadowModeErrorKind | null;

  readonly verifiedCount: number;
  readonly quarantinedCount: number;
  readonly conflictCount: number;
  readonly deletedCount: number;
  readonly unreadableCount: number;

  readonly vaultSecurityMode: string;

  readonly recordDiagnoses: readonly ShadowModeRecordDiagnosis[];
}

export type ShadowModeErrorKind =
  | 'rpcError'
  | 'stateMachineError'
  | 'unexpectedError'
  | 'featureFlagDisabled'
  | 'repositoryNotEnabled';

export interface ShadowModeRunInput {
  readonly vaultId: string;
  readonly deviceId: string;
  readonly publicSigningKeyB64Url: string;
  readonly vaultEncryptionKey: Uint8Array;
  readonly rpcClient: import('./vaultOpLogRepository').SupabaseRpcClient;
}

export interface ShadowModeRunResult {
  readonly success: boolean;
  readonly diagnosis: ShadowModeVaultDiagnosis;
}
