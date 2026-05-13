// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultOpLogDeviceStore` — minimal persistence for the device
 * identity used by the operation-log layer.
 *
 * Stores only non-secret metadata:
 * - deviceId  (opaque string)
 * - publicSigningKeyB64Url  (base64url-encoded SPKI, already public)
 *
 * Does NOT store:
 * - private signing keys
 * - vault encryption keys
 * - plaintexts or passwords
 *
 * Data lifecycle:
 *   - Written once during device-key migration (Phase 7).
 *     The write call site is in the migration orchestrator;
 *     until Phase 7 is complete this store may be empty.
 *   - Read on every unlock when Phase 9 UI is enabled.
 *   - Cleared on explicit logout or vault reset.
 */

const STORAGE_KEY = 'singra_vault_oplog_device_identity' as const;

export interface VaultOpLogDeviceIdentity {
  readonly deviceId: string;
  readonly publicSigningKeyB64Url: string;
}

function isDeviceIdentity(value: unknown): value is VaultOpLogDeviceIdentity {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return typeof obj.deviceId === 'string'
    && obj.deviceId.length > 0
    && typeof obj.publicSigningKeyB64Url === 'string'
    && obj.publicSigningKeyB64Url.length > 0;
}

export function saveVaultOpLogDeviceIdentity(identity: VaultOpLogDeviceIdentity): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(identity));
  } catch {
    // Best-effort only; failures are non-fatal.
  }
}

export function loadVaultOpLogDeviceIdentity(): VaultOpLogDeviceIdentity | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw) as unknown;
    if (!isDeviceIdentity(parsed)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function clearVaultOpLogDeviceIdentity(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Best-effort only.
  }
}
