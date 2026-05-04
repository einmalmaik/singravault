// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Feature flags for the vault operation log repository layer (Phase 3).
 *
 * The new repository path is strictly opt-in.  Default is `false` so
 * that existing UI, VaultContext, Autofill, Export, Search and
 * Clipboard paths cannot accidentally use unfinished infrastructure.
 *
 * Activation:
 *   VITE_VAULT_OP_LOG_REPOSITORY_ENABLED=true
 *
 * No production path may bypass this flag.
 */

const FEATURE_FLAG_ENV_NAME = 'VITE_VAULT_OP_LOG_REPOSITORY_ENABLED' as const;

/**
 * Returns `true` only when the environment explicitly enables the
 * vault operation log repository layer.
 *
 * Conservative default: `false`.
 */
export function isVaultOpLogRepositoryEnabled(): boolean {
  try {
    const value = String((import.meta as { env?: Record<string, unknown> }).env?.[FEATURE_FLAG_ENV_NAME] ?? '');
    return value.trim() === 'true';
  } catch {
    return false;
  }
}
