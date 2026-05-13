// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Vault security states for records and the vault as a whole (Phase 5).
 *
 * Every record has exactly one `RecordSecurityState`.
 * The vault has exactly one `VaultSecurityMode`.
 *
 * These are pure types and policy helpers. No crypto lives here.
 */

import type { SignedVaultOperationV1, TrustedDeviceRecordV1 } from './types';

// ---------------------------------------------------------------------------
// Record security states
// ---------------------------------------------------------------------------

export type RecordSecurityState =
  | 'verified'
  | 'pendingVerification'
  | 'conflict'
  | 'quarantinedTampered'
  | 'quarantinedUnknownAuthor'
  | 'quarantinedMissingWithoutDelete'
  | 'quarantinedUnreadable'
  | 'quarantinedInvalidSchema'
  | 'containerQuarantined'
  | 'deletedByTrustedDevice'
  | 'restoredFromSnapshot';

// ---------------------------------------------------------------------------
// Vault security modes
// ---------------------------------------------------------------------------

export type VaultSecurityMode =
  | 'normal'
  | 'restricted'
  | 'safeMode'
  | 'safeModeRecommended'
  | 'lockedCritical';

// ---------------------------------------------------------------------------
// Operation verification result
// ---------------------------------------------------------------------------

export type OperationVerificationResult =
  | {
      readonly kind: 'validTrustedOperation';
      readonly signedOperation: SignedVaultOperationV1;
    }
  | {
      readonly kind: 'unknownAuthor';
      readonly reason: string;
    }
  | {
      readonly kind: 'revokedAuthor';
      readonly device: TrustedDeviceRecordV1;
      readonly reason: string;
    }
  | { readonly kind: 'invalidSignature' }
  | { readonly kind: 'opHashMismatch' }
  | { readonly kind: 'unsupportedOperationType' }
  | { readonly kind: 'causalGap' }
  | { readonly kind: 'rollbackSuspected' }
  | { readonly kind: 'payloadHashMismatch' }
  | { readonly kind: 'conflictCandidate' }
  | { readonly kind: 'requiresSafeMode' }
  | { readonly kind: 'requiresLockedCritical' };

// ---------------------------------------------------------------------------
// Record context verification result
// ---------------------------------------------------------------------------

export type RecordContextVerificationResult =
  | { readonly kind: 'validContext'; mayDecrypt: true }
  | { readonly kind: 'aadMismatch'; mayDecrypt: false }
  | { readonly kind: 'ciphertextHashMismatch'; mayDecrypt: false }
  | { readonly kind: 'lastOpIdMismatch'; mayDecrypt: false }
  | { readonly kind: 'payloadHashMismatch'; mayDecrypt: false }
  | { readonly kind: 'invalidSchema'; mayDecrypt: false };

// ---------------------------------------------------------------------------
// Decrypt decision gate
// ---------------------------------------------------------------------------

/**
 * The single place that decides whether a record may be decrypted.
 *
 * Returns `true` only when both operation and record context are fully
 * verified. Every negative case blocks decryption.
 */
export function canDecryptVerifiedRecordContext(
  opResult: OperationVerificationResult,
  ctxResult: RecordContextVerificationResult,
): boolean {
  if (opResult.kind !== 'validTrustedOperation') {
    return false;
  }
  if (ctxResult.kind !== 'validContext') {
    return false;
  }
  return ctxResult.mayDecrypt === true;
}
