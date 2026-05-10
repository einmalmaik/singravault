// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Local recovery-code trust state for the vault operation log.
 *
 * Recovery codes are not a server-side shortcut into device trust.
 * The server validates and consumes the single-use code, while clients
 * keep the public commitments in the verified operation log and accept
 * `recover_device` only if it matches an active, previously signed set.
 */

import { VaultSignatureError, type SignedVaultOperationV1 } from './types';

export interface RecoveryCodeSetState {
  readonly vaultId: string;
  readonly setId: string;
  readonly status: 'active' | 'rotated';
  readonly commitments: readonly string[];
  readonly usedCommitments: ReadonlySet<string>;
  readonly createdByDeviceId: string;
  readonly activatedAt: string;
}

export interface RecoveryCodeTrustInput {
  readonly vaultId: string;
  readonly recoveryCodeSetsById: ReadonlyMap<string, RecoveryCodeSetState>;
}

export function applyRecoveryCodeRotationOperation(
  sets: ReadonlyMap<string, RecoveryCodeSetState>,
  op: SignedVaultOperationV1,
): Map<string, RecoveryCodeSetState> {
  if (op.body.opType !== 'recovery_codes_rotate') {
    throw new VaultSignatureError('signed_body_invalid', 'operation is not a recovery code rotation');
  }
  if (op.body.recordType !== 'manifest') {
    throw new VaultSignatureError('signed_body_invalid', 'recovery code rotation must target a manifest record');
  }
  const setId = op.body.recoveryCodeSetId ?? null;
  const commitments = op.body.recoveryCodeCommitments ?? null;
  if (!setId || op.body.recordId !== setId || !Array.isArray(commitments) || commitments.length === 0) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery code rotation is missing set data');
  }
  if (commitments.length > 5) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery code rotation contains too many codes');
  }
  if (new Set(commitments).size !== commitments.length) {
    throw new VaultSignatureError('signed_body_invalid', 'recovery code commitments must be unique');
  }

  const next = new Map<string, RecoveryCodeSetState>();
  for (const [existingSetId, existing] of sets.entries()) {
    next.set(existingSetId, existing.status === 'active'
      ? { ...existing, status: 'rotated' }
      : existing);
  }
  next.set(setId, {
    vaultId: op.body.vaultId,
    setId,
    status: 'active',
    commitments: [...commitments],
    usedCommitments: new Set(),
    createdByDeviceId: op.body.authorDeviceId,
    activatedAt: op.body.createdAtClient,
  });
  return next;
}

export function canRecoverDeviceFromCodeSet(
  op: SignedVaultOperationV1,
  recoveryTrust: RecoveryCodeTrustInput,
): boolean {
  if (op.body.opType !== 'recover_device' || op.body.vaultId !== recoveryTrust.vaultId) {
    return false;
  }
  if (op.body.recordType !== 'device' || op.body.recordId !== op.body.authorDeviceId) {
    return false;
  }
  if (!op.body.targetPublicSigningKey || !op.body.recoveryCodeSetId || !op.body.recoveryCodeCommitment) {
    return false;
  }

  const set = recoveryTrust.recoveryCodeSetsById.get(op.body.recoveryCodeSetId);
  if (!set || set.vaultId !== op.body.vaultId || set.status !== 'active') {
    return false;
  }
  if (!set.commitments.includes(op.body.recoveryCodeCommitment)) {
    return false;
  }
  return !set.usedCommitments.has(op.body.recoveryCodeCommitment);
}

export function markRecoveryCodeCommitmentUsed(
  sets: ReadonlyMap<string, RecoveryCodeSetState>,
  op: SignedVaultOperationV1,
): Map<string, RecoveryCodeSetState> {
  if (op.body.opType !== 'recover_device') {
    throw new VaultSignatureError('signed_body_invalid', 'operation is not a recovery-device operation');
  }
  const setId = op.body.recoveryCodeSetId ?? null;
  const commitment = op.body.recoveryCodeCommitment ?? null;
  if (!setId || !commitment) {
    throw new VaultSignatureError('signed_body_invalid', 'recover_device is missing recovery commitment');
  }
  const existing = sets.get(setId);
  if (!existing || existing.status !== 'active' || !existing.commitments.includes(commitment)) {
    throw new VaultSignatureError('signed_body_invalid', 'recover_device references an inactive or unknown recovery code set');
  }
  if (existing.usedCommitments.has(commitment)) {
    throw new VaultSignatureError('signed_body_invalid', 'recover_device reuses a recovery commitment');
  }
  const next = new Map(sets);
  next.set(setId, {
    ...existing,
    usedCommitments: new Set([...existing.usedCommitments, commitment]),
  });
  return next;
}
