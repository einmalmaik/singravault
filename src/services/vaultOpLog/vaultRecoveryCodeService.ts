// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Client facade for vault device-trust recovery codes.
 *
 * The server generates and validates high-entropy one-time codes.
 * The client only keeps public commitments in signed operations and
 * never stores the plaintext codes after the download flow completes.
 */

import { invokeAuthedFunction } from '@/services/edgeFunctionService';
import { canonicalizeVaultStructure } from './canonicalJson';
import { sha256Base64Url } from './recordHashes';
import { APP_NAMESPACE } from './types';
import type { VaultOperationRow } from './vaultOpLogRpcTypes';

const FUNCTION_NAME = 'vault-recovery-codes';
const RECOVERY_CODE_BODY_LENGTH = 26;
const RECOVERY_CODE_ALPHABET_PATTERN = /^[A-Z2-9]{26}$/u;

export interface VaultRecoveryCodeStatus {
  readonly hasActiveSet: boolean;
  readonly activeSetId: string | null;
  readonly remainingCodes: number;
}

export interface PreparedVaultRecoveryCodeSet {
  readonly setId: string;
  readonly codes: readonly string[];
  readonly commitments: readonly string[];
  readonly createdAt: string;
}

export async function getVaultRecoveryCodeStatus(
  vaultId: string,
): Promise<VaultRecoveryCodeStatus> {
  const response = await invokeAuthedFunction<VaultRecoveryCodeStatus>(FUNCTION_NAME, {
    action: 'status',
    vaultId,
  });
  return response;
}

export async function prepareVaultRecoveryCodes(
  vaultId: string,
): Promise<PreparedVaultRecoveryCodeSet> {
  return invokeAuthedFunction<PreparedVaultRecoveryCodeSet>(FUNCTION_NAME, {
    action: 'prepare-code-set',
    vaultId,
  });
}

export async function activateVaultRecoveryCodeSet(input: {
  readonly vaultId: string;
  readonly setId: string;
  readonly operation: VaultOperationRow;
}): Promise<{ readonly applied: boolean; readonly currentHead: string | null }> {
  return invokeAuthedFunction(FUNCTION_NAME, {
    action: 'activate-code-set',
    vaultId: input.vaultId,
    setId: input.setId,
    operation: input.operation,
  });
}

export async function redeemVaultRecoveryCode(input: {
  readonly vaultId: string;
  readonly requestId: string;
  readonly recoveryCode: string;
  readonly operation: VaultOperationRow;
}): Promise<{ readonly applied: boolean; readonly currentHead: string | null }> {
  return invokeAuthedFunction(FUNCTION_NAME, {
    action: 'redeem-code',
    vaultId: input.vaultId,
    requestId: input.requestId,
    recoveryCode: input.recoveryCode,
    operation: input.operation,
  });
}

export function normalizeVaultRecoveryCode(value: string): string {
  const compact = value
    .normalize('NFKC')
    .toUpperCase()
    .replace(/[\s-]+/gu, '');
  return compact.startsWith('SVR') && compact.length === RECOVERY_CODE_BODY_LENGTH + 3
    ? compact.slice(3)
    : compact;
}

export function isNormalizedVaultRecoveryCode(value: string): boolean {
  return RECOVERY_CODE_ALPHABET_PATTERN.test(value);
}

export async function computeVaultRecoveryCodeCommitment(input: {
  readonly vaultId: string;
  readonly setId: string;
  readonly recoveryCode: string;
}): Promise<string> {
  const normalizedCode = normalizeVaultRecoveryCode(input.recoveryCode);
  if (!isNormalizedVaultRecoveryCode(normalizedCode)) {
    throw new Error(`Recovery-Code muss ${RECOVERY_CODE_BODY_LENGTH} Zeichen enthalten.`);
  }
  const payload = canonicalizeVaultStructure({
    app: APP_NAMESPACE,
    purpose: 'vault-device-recovery-code-commitment-v1',
    vaultId: input.vaultId,
    setId: input.setId,
    code: normalizedCode,
  });
  return sha256Base64Url(payload);
}

export function formatVaultRecoveryCodesDownload(input: {
  readonly vaultId: string;
  readonly setId: string;
  readonly codes: readonly string[];
  readonly createdAt: string;
}): string {
  return [
    'Singra Vault Recovery-Codes fuer Geraetezugriff',
    '',
    'Diese Codes sind die letzte Wiederherstellungsmoeglichkeit, wenn kein vertrauenswuerdiges Geraet mehr verfuegbar ist.',
    'Jeder Code ist nur einmal nutzbar. Singra Support kann diese Codes nicht wiederherstellen.',
    '',
    `Vault-ID: ${input.vaultId}`,
    `Recovery-Set-ID: ${input.setId}`,
    `Erstellt: ${input.createdAt}`,
    '',
    ...input.codes.map((code, index) => `${index + 1}. ${code}`),
    '',
    'Bewahre diese Datei offline und sicher auf. Wer Masterpasswort, Kontozugriff und einen dieser Codes besitzt, kann ein neues Geraet fuer diesen Tresor freischalten.',
  ].join('\n');
}
