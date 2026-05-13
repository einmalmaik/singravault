// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Shared blocker for old runtime writes to legacy vault tables.
 *
 * Until the signed operation-log mutation path is wired end-to-end, runtime
 * flows must fail closed instead of writing `vault_items` or `categories`.
 */

export const LEGACY_VAULT_WRITE_BLOCKED_MESSAGE =
  'Diese Aktion ist bis zur kontrollierten Tresor-Migration deaktiviert.';

export class LegacyVaultRuntimeWriteBlockedError extends Error {
  constructor(public readonly action: string) {
    super(`${LEGACY_VAULT_WRITE_BLOCKED_MESSAGE} Aktion: ${action}.`);
    this.name = 'LegacyVaultRuntimeWriteBlockedError';
  }
}

export function createLegacyVaultRuntimeWriteBlockedError(action: string): LegacyVaultRuntimeWriteBlockedError {
  return new LegacyVaultRuntimeWriteBlockedError(action);
}

export function blockLegacyVaultRuntimeWrite(action: string): never {
  throw createLegacyVaultRuntimeWriteBlockedError(action);
}
