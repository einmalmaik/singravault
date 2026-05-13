// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Feature flags for the vault operation log repository layer.
 *
 * Phase 11 removed all old runtime security logic (rebaseline, snapshot-digest
 * trust, TTL-based trust, category global blockade, direct old vault writes).
 * These flags are now hard-coded structural stubs for Phase 12 rollout
 * planning. They MUST NOT reactivate old security logic.
 *
 * - Repository enabled: true  (new model is the only runtime path)
 * - Shadow mode enabled: false (no parallel old logic to shadow against)
 * - Phase 9 UI enabled: true  (security-mode UI is mandatory)
 */

export function isVaultOpLogRepositoryEnabled(): boolean {
  return true;
}

/**
 * Shadow mode is permanently disabled after Phase 11.
 * If diagnostics are needed, they must be read-only and must never
 * execute old integration, rebaseline, digest, TTL or quarantine paths.
 */
export function isVaultOpLogShadowModeEnabled(): boolean {
  return false;
}

export function isVaultOpLogPhase9UIEnabled(): boolean {
  return true;
}
