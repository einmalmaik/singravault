// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `deviceTrustService` — pure classification of operation authors
 * against a trust list.
 *
 * This module takes no storage. The trust list is supplied by the
 * caller, already decrypted and verified as part of the vault
 * provider state. The module's job is to answer one question for a
 * given operation: may it advance the vault state?
 *
 * The answer is one of:
 *
 *  - `trusted` — the author device was on the trust list at the
 *    operation's `trust_epoch` and was not revoked before the
 *    operation's `created_at_client`.
 *  - `revoked` — the author device was revoked at or before the
 *    operation's `created_at_client`.
 *  - `unknown` — the author is not on the trust list for the vault,
 *    or is on a trust list for a different vault, or is on the list
 *    with a different `trust_epoch` than the operation claims.
 */

import {
  VaultSignatureError,
  type AuthorTrustClassification,
  type SignedVaultOperationV1,
  type TrustedDeviceRecordV1,
} from './types';

export interface TrustListInput {
  readonly vaultId: string;
  readonly trustedDevicesById: ReadonlyMap<string, TrustedDeviceRecordV1>;
}

/**
 * Classify the author of a signed operation. Deliberately does not
 * call WebCrypto: signature verification lives in
 * `operationSigningService`. This module only answers the trust
 * question, so that a state machine can compose signature + trust
 * in a single verification step.
 */
export function classifyOperationAuthor(
  op: SignedVaultOperationV1,
  trust: TrustListInput,
): AuthorTrustClassification {
  if (op.body.vaultId !== trust.vaultId) {
    return { status: 'unknown', reason: 'device_wrong_vault' };
  }

  const device = trust.trustedDevicesById.get(op.body.authorDeviceId);
  if (!device) {
    return { status: 'unknown', reason: 'device_not_in_trust_list' };
  }

  if (device.vaultId !== trust.vaultId) {
    return { status: 'unknown', reason: 'device_wrong_vault' };
  }

  if (op.body.trustEpoch !== device.trustEpoch) {
    return { status: 'unknown', reason: 'device_trust_epoch_mismatch' };
  }

  if (device.status === 'revoked') {
    if (device.revokedAt && isBeforeOrEqual(device.revokedAt, op.body.createdAtClient)) {
      return { status: 'revoked', device, reason: 'revoked_before_op' };
    }
    // Device is revoked but the operation was authored before the
    // revocation — historically valid but not an authoritative root
    // for new state. We still classify this as `revoked` so the
    // state machine treats it conservatively.
    return { status: 'revoked', device, reason: 'revoked_before_op' };
  }

  return { status: 'trusted', device };
}

/**
 * Apply an `add_device` or `revoke_device` operation to an existing
 * trust list, producing a new list. The caller is responsible for
 * having already verified the signed operation with
 * `verifyOperationSignature` and the author with
 * `classifyOperationAuthor`. This module never bypasses those
 * checks, it only updates state once they pass.
 */
export function applyDeviceTrustOperation(
  list: ReadonlyMap<string, TrustedDeviceRecordV1>,
  op: SignedVaultOperationV1,
  payload: DeviceTrustOperationPayload,
): Map<string, TrustedDeviceRecordV1> {
  const next = new Map(list);
  if (op.body.recordType !== 'device') {
    throw new VaultSignatureError('signed_body_invalid', 'device trust operation must target a device record');
  }
  if (op.body.opType === 'add_device') {
    if (payload.kind !== 'add') {
      throw new VaultSignatureError('signed_body_invalid', 'payload does not match add_device op');
    }
    if (payload.device.deviceId !== op.body.recordId) {
      throw new VaultSignatureError('signed_body_invalid', 'added device does not match signed target device');
    }
    if (payload.device.publicSigningKey !== op.body.targetPublicSigningKey) {
      throw new VaultSignatureError('signed_body_invalid', 'added device key does not match signed target key');
    }
    if (next.has(payload.device.deviceId)) {
      throw new VaultSignatureError('signed_body_invalid', 'device already present in trust list');
    }
    if (payload.device.vaultId !== op.body.vaultId) {
      throw new VaultSignatureError('signed_body_invalid', 'added device belongs to another vault');
    }
    next.set(payload.device.deviceId, payload.device);
    return next;
  }
  if (op.body.opType === 'revoke_device') {
    if (payload.kind !== 'revoke') {
      throw new VaultSignatureError('signed_body_invalid', 'payload does not match revoke_device op');
    }
    if (payload.deviceId !== op.body.recordId) {
      throw new VaultSignatureError('signed_body_invalid', 'revoked device does not match signed target device');
    }
    const existing = next.get(payload.deviceId);
    if (!existing) {
      throw new VaultSignatureError('signed_body_invalid', 'device to revoke not present');
    }
    next.set(payload.deviceId, {
      ...existing,
      status: 'revoked',
      revokedAt: payload.revokedAt,
      revokedByDeviceId: op.body.authorDeviceId,
      trustEpoch: existing.trustEpoch + 1,
    });
    return next;
  }
  throw new VaultSignatureError('signed_body_invalid', `not a device-trust op type: ${op.body.opType}`);
}

export type DeviceTrustOperationPayload =
  | { readonly kind: 'add'; readonly device: TrustedDeviceRecordV1 }
  | { readonly kind: 'revoke'; readonly deviceId: string; readonly revokedAt: string };

/**
 * Helper: check whether a device is currently trusted. This is a
 * snapshot check, not a classification against a specific
 * operation.
 */
export function isDeviceCurrentlyTrusted(
  device: TrustedDeviceRecordV1,
): boolean {
  return device.status === 'trusted';
}

function isBeforeOrEqual(isoA: string, isoB: string): boolean {
  const timeA = Date.parse(isoA);
  const timeB = Date.parse(isoB);
  if (Number.isNaN(timeA) || Number.isNaN(timeB)) {
    // If either timestamp cannot be parsed the safe answer is that
    // the revocation covers the operation — conservative trust.
    return true;
  }
  return timeA <= timeB;
}
