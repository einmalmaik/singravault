// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Pure policy for the OpLog offline runtime gates.
 *
 * This module performs no crypto and no storage I/O. It makes the three gates
 * explicit and testable:
 * 1. token-free offline account context,
 * 2. vault-key unlock with Device-Key-required fail-closed semantics,
 * 3. verified local working set plus local device signing trust for writes.
 */

import { requiresDeviceKey, type VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';

export type OfflineVaultSecurityMode =
  | 'offlineLocked'
  | 'offlineReadOnly'
  | 'offlineReady'
  | 'restricted'
  | 'safeMode'
  | 'lockedCritical';

export type OfflineGateFailureReason =
  | 'offline_identity_missing'
  | 'offline_identity_contains_auth_token'
  | 'vault_id_missing'
  | 'vault_key_missing'
  | 'device_key_missing'
  | 'device_key_invalid'
  | 'verified_working_set_missing'
  | 'verified_working_set_invalid'
  | 'local_signing_key_missing'
  | 'local_signing_key_mismatch'
  | 'local_device_revoked'
  | 'local_device_not_trusted';

export interface OfflineIdentityContext {
  readonly userId: string;
  readonly email: string;
  readonly updatedAt: string;
  readonly vaultId: string | null;
}

export interface VaultKeyUnlockGate {
  readonly vaultKeyAvailable: boolean;
  readonly protectionMode: VaultProtectionMode;
  readonly deviceKeyAvailable: boolean;
  readonly deviceKeyVerified: boolean;
}

export interface LocalTrustWorkingSetGate {
  readonly exists: boolean;
  readonly structureValid: boolean;
  readonly manifestVerified: boolean;
  readonly opLogComplete: boolean;
  readonly lastVerifiedVaultHead: string | null;
  readonly lastVerifiedSequence: number | null;
  readonly trustEpoch: number | null;
}

export interface LocalDeviceSigningTrustGate {
  readonly privateSigningKeyAvailable: boolean;
  readonly publicKeyMatchesTrustedDevice: boolean;
  readonly deviceTrustedAtHead: boolean;
  readonly deviceRevokedAtHead: boolean;
}

export interface OfflineGateEvaluationInput {
  readonly identity: unknown;
  readonly unlock: VaultKeyUnlockGate;
  readonly workingSet: LocalTrustWorkingSetGate | null;
  readonly signingTrust: LocalDeviceSigningTrustGate | null;
  readonly allowReadOnlyWithoutSigningKey?: boolean;
}

export interface OfflineGateEvaluation {
  readonly mode: OfflineVaultSecurityMode;
  readonly canReadVerifiedRecords: boolean;
  readonly canWriteSignedPendingOperations: boolean;
  readonly reason: OfflineGateFailureReason | null;
}

export function evaluateOfflineVaultGates(
  input: OfflineGateEvaluationInput,
): OfflineGateEvaluation {
  const identity = validateOfflineIdentity(input.identity);
  if (identity.kind !== 'valid') {
    return locked(identity.reason);
  }

  if (!identity.identity.vaultId) {
    return locked('vault_id_missing');
  }

  if (!input.unlock.vaultKeyAvailable) {
    return locked('vault_key_missing');
  }

  if (requiresDeviceKey(input.unlock.protectionMode)) {
    if (!input.unlock.deviceKeyAvailable) {
      return locked('device_key_missing');
    }
    if (!input.unlock.deviceKeyVerified) {
      return locked('device_key_invalid');
    }
  }

  if (!input.workingSet?.exists) {
    return locked('verified_working_set_missing');
  }

  if (
    !input.workingSet.structureValid
    || !input.workingSet.manifestVerified
    || !input.workingSet.opLogComplete
    || !input.workingSet.lastVerifiedVaultHead
    || !Number.isSafeInteger(input.workingSet.lastVerifiedSequence)
    || !Number.isSafeInteger(input.workingSet.trustEpoch)
  ) {
    return locked('verified_working_set_invalid');
  }

  const signingTrust = input.signingTrust;
  if (!signingTrust?.privateSigningKeyAvailable) {
    return readOnlyOrLocked(input.allowReadOnlyWithoutSigningKey === true, 'local_signing_key_missing');
  }
  if (!signingTrust.publicKeyMatchesTrustedDevice) {
    return readOnlyOrLocked(input.allowReadOnlyWithoutSigningKey === true, 'local_signing_key_mismatch');
  }
  if (signingTrust.deviceRevokedAtHead) {
    return readOnlyOrLocked(input.allowReadOnlyWithoutSigningKey === true, 'local_device_revoked');
  }
  if (!signingTrust.deviceTrustedAtHead) {
    return readOnlyOrLocked(input.allowReadOnlyWithoutSigningKey === true, 'local_device_not_trusted');
  }

  return {
    mode: 'offlineReady',
    canReadVerifiedRecords: true,
    canWriteSignedPendingOperations: true,
    reason: null,
  };
}

export function validateOfflineIdentity(
  value: unknown,
): { readonly kind: 'valid'; readonly identity: OfflineIdentityContext } | { readonly kind: 'invalid'; readonly reason: OfflineGateFailureReason } {
  if (!value || typeof value !== 'object') {
    return { kind: 'invalid', reason: 'offline_identity_missing' };
  }

  const candidate = value as Record<string, unknown>;
  if (
    'access_token' in candidate
    || 'refresh_token' in candidate
    || 'accessToken' in candidate
    || 'refreshToken' in candidate
    || 'session' in candidate
  ) {
    return { kind: 'invalid', reason: 'offline_identity_contains_auth_token' };
  }

  if (
    typeof candidate.userId !== 'string'
    || candidate.userId.length === 0
    || typeof candidate.email !== 'string'
    || candidate.email.length === 0
    || typeof candidate.updatedAt !== 'string'
    || candidate.updatedAt.length === 0
    || (candidate.vaultId !== null && candidate.vaultId !== undefined && typeof candidate.vaultId !== 'string')
  ) {
    return { kind: 'invalid', reason: 'offline_identity_missing' };
  }

  return {
    kind: 'valid',
    identity: {
      userId: candidate.userId,
      email: candidate.email,
      updatedAt: candidate.updatedAt,
      vaultId: candidate.vaultId ?? null,
    },
  };
}

function locked(reason: OfflineGateFailureReason): OfflineGateEvaluation {
  return {
    mode: 'offlineLocked',
    canReadVerifiedRecords: false,
    canWriteSignedPendingOperations: false,
    reason,
  };
}

function readOnlyOrLocked(
  allowReadOnly: boolean,
  reason: OfflineGateFailureReason,
): OfflineGateEvaluation {
  if (!allowReadOnly) {
    return locked(reason);
  }
  return {
    mode: 'offlineReadOnly',
    canReadVerifiedRecords: true,
    canWriteSignedPendingOperations: false,
    reason,
  };
}
