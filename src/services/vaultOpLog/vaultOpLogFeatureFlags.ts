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
const SHADOW_MODE_FLAG_ENV_NAME = 'VITE_VAULT_OP_LOG_SHADOW_MODE_ENABLED' as const;
const PHASE_9_UI_FLAG_ENV_NAME = 'VITE_VAULT_OP_LOG_PHASE_9_UI_ENABLED' as const;

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

/**
 * Returns `true` only when the environment explicitly enables the
 * vault operation log shadow mode (Phase 8).
 *
 * Shadow mode runs the new state machine in the background without
 * switching UI, Autofill, Export, Search or Clipboard to the new
 * data. It produces only sanitised diagnostics.
 *
 * Conservative default: `false`.
 */
export function isVaultOpLogShadowModeEnabled(): boolean {
  try {
    const value = String((import.meta as { env?: Record<string, unknown> }).env?.[SHADOW_MODE_FLAG_ENV_NAME] ?? '');
    return value.trim() === 'true';
  } catch {
    return false;
  }
}

/**
 * Returns `true` only when the environment explicitly enables the
 * Phase 9 UI integration for vault security modes, quarantine,
 * conflicts and safe mode display.
 *
 * Phase 9 UI is strictly opt-in and separate from Shadow Mode.
 * When disabled, the old productive vault path remains unchanged.
 *
 * Conservative default: `false`.
 */
export function isVaultOpLogPhase9UIEnabled(): boolean {
  try {
    const value = String((import.meta as { env?: Record<string, unknown> }).env?.[PHASE_9_UI_FLAG_ENV_NAME] ?? '');
    return value.trim() === 'true';
  } catch {
    return false;
  }
}
