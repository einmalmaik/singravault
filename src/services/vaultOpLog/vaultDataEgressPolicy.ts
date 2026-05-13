// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultDataEgressPolicy` — Phase 10 central policy layer for all
 * security-critical data egress paths.
 *
 * Decides whether a vault record may be:
 *   - exported
 *   - included in the search index
 *   - copied to clipboard
 *   - used for autofill
 *
 * Rules:
 *   - Deny-by-default: unknown state, missing state, or error means NO egress.
 *   - Only `verified` and `restoredFromSnapshot` records are eligible.
 *   - `lockedCritical`, `safeMode`, and `safeModeRecommended` block egress.
 *   - Quarantined, pending, conflict, and unknown-author records are excluded.
 *   - Password autofill is NEVER allowed — `canUseRecordForAutofill` always
 *     returns `false`.
 *
 * This module is pure: no crypto, no UI, no I/O, no logging of secrets.
 */

import type { RecordSecurityState, VaultSecurityMode } from './vaultSecurityStates';
import type { VaultOpLogUiView } from './vaultOpLogUiAdapter';

// ---------------------------------------------------------------------------
// Record state helpers
// ---------------------------------------------------------------------------

/**
 * Returns `true` only for record states that are fully verified and
 * safe for any kind of data egress.
 */
export function isRecordSecurityStateVerifiedForEgress(
  recordState: RecordSecurityState,
): boolean {
  return recordState === 'verified' || recordState === 'restoredFromSnapshot';
}

/**
 * Returns `true` for record states that must never reach any egress path.
 *
 * This is the exact negation of `isRecordSecurityStateVerifiedForEgress`.
 * Any state that is not explicitly verified is blocked (deny-by-default).
 */
export function isRecordSecurityStateBlockingEgress(
  recordState: RecordSecurityState,
): boolean {
  return !isRecordSecurityStateVerifiedForEgress(recordState);
}

// ---------------------------------------------------------------------------
// Vault mode helpers
// ---------------------------------------------------------------------------

/**
 * Returns `true` when the vault security mode is so restrictive that
 * NO record should be exported, indexed, copied, or autofilled.
 */
export function isVaultSecurityModeBlockingEgress(
  vaultMode: VaultSecurityMode,
): boolean {
  switch (vaultMode) {
    case 'normal':
    case 'restricted':
      return false;
    case 'safeMode':
    case 'safeModeRecommended':
    case 'lockedCritical':
      return true;
    default:
      // Deny-by-default for unknown modes.
      return true;
  }
}

// ---------------------------------------------------------------------------
// Internal egress gate
// ---------------------------------------------------------------------------

/**
 * Shared implementation for all egress paths.
 *
 * Returns `true` only when:
 *   - the vault mode is NOT blocking (`normal` or `restricted`)
 *   - the record state is verified (`verified` or `restoredFromSnapshot`)
 *
 * Every other combination is deny-by-default.
 */
function _isEgressAllowed(
  recordState: RecordSecurityState,
  vaultMode: VaultSecurityMode,
): boolean {
  if (isVaultSecurityModeBlockingEgress(vaultMode)) {
    return false;
  }
  return isRecordSecurityStateVerifiedForEgress(recordState);
}

// ---------------------------------------------------------------------------
// Egress policy gates
// ---------------------------------------------------------------------------

/**
 * Determines whether a record may be exported.
 *
 * Allowed: `verified`, `restoredFromSnapshot` in `normal` or `restricted`.
 * Blocked: everything else, and all modes >= safeMode.
 */
export function canExportRecord(
  recordState: RecordSecurityState,
  vaultMode: VaultSecurityMode,
): boolean {
  return _isEgressAllowed(recordState, vaultMode);
}

/**
 * Determines whether a record may be included in the search index.
 *
 * Same rules as export: only verified records in normal/restricted mode.
 * When the vault enters safeMode or lockedCritical, index entries must
 * be removed or invalidated by the caller.
 */
export function canIndexRecord(
  recordState: RecordSecurityState,
  vaultMode: VaultSecurityMode,
): boolean {
  return _isEgressAllowed(recordState, vaultMode);
}

/**
 * Determines whether a record's secret may be copied to clipboard.
 *
 * Same rules as export: only verified records in normal/restricted mode.
 * The caller must ensure the copy happens only after an explicit user action.
 */
export function canCopyRecordSecret(
  recordState: RecordSecurityState,
  vaultMode: VaultSecurityMode,
): boolean {
  return _isEgressAllowed(recordState, vaultMode);
}

/**
 * Determines whether a record may be used for password autofill.
 *
 * IMPORTANT: This function ALWAYS returns `false`.
 *
 * Product decision (Phase 10): Password autofill is NOT activated.
 * Existing autofill entry-points must remain blocked in the new
 * OpLog/Phase-10 path. Passwords must never be automatically injected
 * into web pages, forms, extensions, or external contexts.
 *
 * If legacy code uses "autofill" for non-secret local suggestions
 * (e.g. username hints), that path must be clearly separated and
 * documented by the caller. This gate covers only secret autofill.
 */
export function canUseRecordForAutofill(
  _recordState: RecordSecurityState,
  _vaultMode: VaultSecurityMode,
): boolean {
  // Product decision: password autofill is permanently disabled.
  return false;
}

// ---------------------------------------------------------------------------
// UI bridge helpers — translate VaultOpLogUiView into egress decisions
// ---------------------------------------------------------------------------

/**
 * Builds a `Set<string>` of record IDs that must be excluded from export
 * based on the current OpLog UI view.
 *
 * Returns `null` when `opLogUiView` is not available (feature flag off or
 * orchestrator not loaded). In that case the caller should fall back to
 * the legacy integrity path.
 *
 * When `opLogUiView` IS available, the set contains the IDs of:
 *   - quarantined records
 *   - conflicted records
 *   - deleted-by-trusted-device records
 *
 * IMPORTANT: This function does NOT check `vaultSecurityMode`.
 * The caller must additionally call `isVaultSecurityModeBlockingEgress`
 * and abort the export entirely when that returns `true`.
 */
export function buildExcludedItemIdsFromOpLogView(
  opLogUiView: VaultOpLogUiView | null,
): Set<string> | null {
  if (!opLogUiView) {
    return null;
  }

  const excluded = new Set<string>();
  for (const q of opLogUiView.quarantinedItems) {
    excluded.add(q.recordId);
  }
  for (const c of opLogUiView.conflictedItems) {
    excluded.add(c.recordId);
  }
  for (const d of opLogUiView.deletedItemIds) {
    excluded.add(d);
  }
  return excluded;
}

/**
 * Builds a `Set<string>` of record IDs that are verified and therefore
 * eligible for search indexing and clipboard copy.
 *
 * Returns `null` when `opLogUiView` is not available (feature flag off or
 * orchestrator not loaded). In that case the caller should fall back to
 * the legacy integrity path.
 *
 * When the vault security mode is `lockedCritical`, `safeMode`, or
 * `safeModeRecommended`, this returns an **empty** `Set`, meaning NO
 * record may be indexed or copied regardless of individual record state.
 */
export function getVerifiedRecordIdsForEgress(
  opLogUiView: VaultOpLogUiView | null,
): Set<string> | null {
  if (!opLogUiView) {
    return null;
  }

  if (isVaultSecurityModeBlockingEgress(opLogUiView.vaultSecurityMode)) {
    return new Set<string>();
  }

  return new Set(opLogUiView.verifiedItems.map((v) => v.recordId));
}
