// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `vaultOpLogUiAdapter` — Phase 9 UI adapter / selector.
 *
 * Translates a `LocalVaultState` (from the Phase 5 state machine)
 * into UI-friendly structures.  This module makes NO security
 * decisions; it only projects the already-computed security states
 * onto the representation layer.
 *
 * Invariants:
 * - No plaintext secrets are included in the output.
 * - Quarantined records expose only their ID, state and reason code.
 * - Verified records expose only their ID and type metadata.
 * - Conflicts expose only the record ID and involved operation IDs.
 * - The adapter never decrypts; decryption happened inside the state machine.
 */

import type {
  RecordSecurityState,
  VaultSecurityMode,
} from './vaultSecurityStates';
import {
  determineVaultSecurityMode,
  type LocalVaultState,
} from './vaultStateMachine';

// ---------------------------------------------------------------------------
// UI view model
// ---------------------------------------------------------------------------

export interface VaultOpLogVerifiedItemUi {
  readonly recordId: string;
  readonly recordType: string;
  readonly recordVersion: number;
}

export interface VaultOpLogQuarantinedItemUi {
  readonly recordId: string;
  readonly recordState: Extract<
    RecordSecurityState,
    | 'quarantinedTampered'
    | 'quarantinedUnknownAuthor'
    | 'quarantinedMissingWithoutDelete'
    | 'quarantinedUnreadable'
    | 'quarantinedInvalidSchema'
    | 'containerQuarantined'
  >;
  readonly reason: string;
}

export interface VaultOpLogConflictUi {
  readonly recordId: string;
  readonly operationCount: number;
  readonly operationIds: readonly string[];
}

export interface VaultOpLogUiView {
  readonly vaultSecurityMode: VaultSecurityMode;
  readonly verifiedItems: readonly VaultOpLogVerifiedItemUi[];
  readonly quarantinedItems: readonly VaultOpLogQuarantinedItemUi[];
  readonly conflictedItems: readonly VaultOpLogConflictUi[];
  readonly deletedItemIds: readonly string[];
  readonly restoredItemIds: readonly string[];
}

// ---------------------------------------------------------------------------
// Record state → UI label (i18n-safe code)
// ---------------------------------------------------------------------------

export function getRecordSecurityStateUiLabel(state: RecordSecurityState): string {
  switch (state) {
    case 'verified':
      return 'verified';
    case 'pendingVerification':
      return 'pendingVerification';
    case 'conflict':
      return 'conflict';
    case 'quarantinedTampered':
      return 'quarantinedTampered';
    case 'quarantinedUnknownAuthor':
      return 'quarantinedUnknownAuthor';
    case 'quarantinedMissingWithoutDelete':
      return 'quarantinedMissingWithoutDelete';
    case 'quarantinedUnreadable':
      return 'quarantinedUnreadable';
    case 'quarantinedInvalidSchema':
      return 'quarantinedInvalidSchema';
    case 'containerQuarantined':
      return 'containerQuarantined';
    case 'deletedByTrustedDevice':
      return 'deletedByTrustedDevice';
    case 'restoredFromSnapshot':
      return 'restoredFromSnapshot';
    default:
      return 'unknown';
  }
}

export function getVaultSecurityModeUiLabel(mode: VaultSecurityMode): string {
  switch (mode) {
    case 'normal':
      return 'normal';
    case 'restricted':
      return 'restricted';
    case 'safeMode':
      return 'safeMode';
    case 'safeModeRecommended':
      return 'safeModeRecommended';
    case 'lockedCritical':
      return 'lockedCritical';
    default:
      return 'unknown';
  }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export function buildVaultOpLogUiView(localVaultState: LocalVaultState): VaultOpLogUiView {
  const verifiedItems: VaultOpLogVerifiedItemUi[] = [];
  const quarantinedItems: VaultOpLogQuarantinedItemUi[] = [];
  const conflictedItems: VaultOpLogConflictUi[] = [];
  const deletedItemIds: string[] = [];
  const restoredItemIds: string[] = [];

  for (const [recordId, localRecord] of localVaultState.recordsById.entries()) {
    const { recordState } = localRecord;

    if (recordState === 'verified') {
      verifiedItems.push({
        recordId,
        recordType: localRecord.record.recordType,
        recordVersion: localRecord.record.recordVersion,
      });
      continue;
    }

    if (recordState === 'deletedByTrustedDevice') {
      deletedItemIds.push(recordId);
      continue;
    }

    if (recordState === 'restoredFromSnapshot') {
      restoredItemIds.push(recordId);
      verifiedItems.push({
        recordId,
        recordType: localRecord.record.recordType,
        recordVersion: localRecord.record.recordVersion,
      });
      continue;
    }

    if (recordState === 'pendingVerification') {
      // Pending records are not shown in the main list and not shown
      // in quarantine either. They are transient.
      continue;
    }

    if (recordState === 'containerQuarantined') {
      // Container quarantine is treated as a quarantine state for the
      // individual record in the UI, but the plaintext is NOT shown.
      quarantinedItems.push({
        recordId,
        recordState: 'containerQuarantined',
        reason: 'containerQuarantined',
      });
      continue;
    }

    if (recordState === 'conflict') {
      // Conflicts are tracked in conflictsByRecordId, not here.
      // If a record somehow has state 'conflict' in recordsById,
      // it is a structural anomaly and should not leak into quarantine UI.
      continue;
    }

    // Any remaining state that is not explicitly handled above is
    // treated as quarantined for UI purposes.
    quarantinedItems.push({
      recordId,
      recordState,
      reason: getRecordSecurityStateUiLabel(recordState),
    });
  }

  for (const [recordId, localConflict] of localVaultState.conflictsByRecordId.entries()) {
    conflictedItems.push({
      recordId,
      operationCount: localConflict.operations.length,
      operationIds: localConflict.operations.map((op) => op.opId),
    });
  }

  // Also include explicit quarantined records map entries
  for (const [recordId, quarantinedRecord] of localVaultState.quarantinedRecordsById.entries()) {
    const existing = quarantinedItems.find((q) => q.recordId === recordId);
    if (!existing) {
      quarantinedItems.push({
        recordId,
        recordState: quarantinedRecord.recordState,
        reason: quarantinedRecord.reason,
      });
    }
  }

  return {
    vaultSecurityMode: determineVaultSecurityMode(localVaultState),
    verifiedItems: Object.freeze(verifiedItems),
    quarantinedItems: Object.freeze(quarantinedItems),
    conflictedItems: Object.freeze(conflictedItems),
    deletedItemIds: Object.freeze(deletedItemIds),
    restoredItemIds: Object.freeze(restoredItemIds),
  };
}

