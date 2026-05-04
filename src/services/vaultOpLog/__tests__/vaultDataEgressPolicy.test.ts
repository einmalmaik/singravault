// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for the vault data egress policy — Phase 10.
 *
 * Security invariants under test:
 * - Only `verified` and `restoredFromSnapshot` records may egress.
 * - `lockedCritical`, `safeMode`, and `safeModeRecommended` block all egress.
 * - Quarantined, pending, conflict, and unknown-author records are blocked.
 * - Password autofill is always denied.
 * - Unknown states are deny-by-default.
 */

import { describe, expect, it } from 'vitest';
import {
  canExportRecord,
  canIndexRecord,
  canCopyRecordSecret,
  canUseRecordForAutofill,
  isRecordSecurityStateVerifiedForEgress,
  isRecordSecurityStateBlockingEgress,
  isVaultSecurityModeBlockingEgress,
  buildExcludedItemIdsFromOpLogView,
  getVerifiedRecordIdsForEgress,
} from '../vaultDataEgressPolicy';
import type { RecordSecurityState, VaultSecurityMode } from '../vaultSecurityStates';
import type { VaultOpLogUiView } from '../vaultOpLogUiAdapter';

// ---------------------------------------------------------------------------
// Record state helpers
// ---------------------------------------------------------------------------

describe('isRecordSecurityStateVerifiedForEgress', () => {
  it.each([
    ['verified', true],
    ['restoredFromSnapshot', true],
    ['pendingVerification', false],
    ['conflict', false],
    ['quarantinedTampered', false],
    ['quarantinedUnknownAuthor', false],
    ['quarantinedMissingWithoutDelete', false],
    ['quarantinedUnreadable', false],
    ['quarantinedInvalidSchema', false],
    ['containerQuarantined', false],
    ['deletedByTrustedDevice', false],
  ] as [RecordSecurityState, boolean][])('returns %s for %s', (state, expected) => {
    expect(isRecordSecurityStateVerifiedForEgress(state)).toBe(expected);
  });
});

describe('isRecordSecurityStateBlockingEgress', () => {
  it.each([
    ['verified', false],
    ['restoredFromSnapshot', false],
    ['pendingVerification', true],
    ['conflict', true],
    ['quarantinedTampered', true],
    ['quarantinedUnknownAuthor', true],
    ['quarantinedMissingWithoutDelete', true],
    ['quarantinedUnreadable', true],
    ['quarantinedInvalidSchema', true],
    ['containerQuarantined', true],
    ['deletedByTrustedDevice', true],
  ] as [RecordSecurityState, boolean][])('returns %s for %s', (state, expected) => {
    expect(isRecordSecurityStateBlockingEgress(state)).toBe(expected);
  });

  it('denies unknown states by default', () => {
    expect(isRecordSecurityStateBlockingEgress('unknown_state' as unknown as RecordSecurityState)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Vault mode helpers
// ---------------------------------------------------------------------------

describe('isVaultSecurityModeBlockingEgress', () => {
  it.each([
    ['normal', false],
    ['restricted', false],
    ['safeMode', true],
    ['safeModeRecommended', true],
    ['lockedCritical', true],
  ] as [VaultSecurityMode, boolean][])('returns %s for %s', (mode, expected) => {
    expect(isVaultSecurityModeBlockingEgress(mode)).toBe(expected);
  });

  it('blocks unknown modes by default', () => {
    expect(isVaultSecurityModeBlockingEgress('unknown_mode' as unknown as VaultSecurityMode)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Export gate
// ---------------------------------------------------------------------------

describe('canExportRecord', () => {
  it('allows verified in normal mode', () => {
    expect(canExportRecord('verified', 'normal')).toBe(true);
  });

  it('allows verified in restricted mode', () => {
    expect(canExportRecord('verified', 'restricted')).toBe(true);
  });

  it('allows restoredFromSnapshot in normal mode', () => {
    expect(canExportRecord('restoredFromSnapshot', 'normal')).toBe(true);
  });

  it('blocks verified in lockedCritical mode', () => {
    expect(canExportRecord('verified', 'lockedCritical')).toBe(false);
  });

  it('blocks verified in safeMode', () => {
    expect(canExportRecord('verified', 'safeMode')).toBe(false);
  });

  it('blocks verified in safeModeRecommended', () => {
    expect(canExportRecord('verified', 'safeModeRecommended')).toBe(false);
  });

  it.each([
    'quarantinedTampered',
    'quarantinedUnknownAuthor',
    'quarantinedMissingWithoutDelete',
    'quarantinedUnreadable',
    'quarantinedInvalidSchema',
  ] as RecordSecurityState[])('blocks %s in normal mode', (state) => {
    expect(canExportRecord(state, 'normal')).toBe(false);
  });

  it('blocks pendingVerification in normal mode', () => {
    expect(canExportRecord('pendingVerification', 'normal')).toBe(false);
  });

  it('blocks conflict in normal mode', () => {
    expect(canExportRecord('conflict', 'normal')).toBe(false);
  });

  it('blocks containerQuarantined in normal mode', () => {
    expect(canExportRecord('containerQuarantined', 'normal')).toBe(false);
  });

  it('blocks deletedByTrustedDevice in normal mode', () => {
    expect(canExportRecord('deletedByTrustedDevice', 'normal')).toBe(false);
  });

  it('blocks unknown state in normal mode (deny-by-default)', () => {
    expect(canExportRecord('unknown_state' as unknown as RecordSecurityState, 'normal')).toBe(false);
  });

  it('blocks unknown vault mode (deny-by-default)', () => {
    expect(canExportRecord('verified', 'unknown_mode' as unknown as VaultSecurityMode)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Search / index gate
// ---------------------------------------------------------------------------

describe('canIndexRecord', () => {
  it('allows verified in normal mode', () => {
    expect(canIndexRecord('verified', 'normal')).toBe(true);
  });

  it('allows verified in restricted mode', () => {
    expect(canIndexRecord('verified', 'restricted')).toBe(true);
  });

  it('allows restoredFromSnapshot in normal mode', () => {
    expect(canIndexRecord('restoredFromSnapshot', 'normal')).toBe(true);
  });

  it('blocks verified in lockedCritical mode', () => {
    expect(canIndexRecord('verified', 'lockedCritical')).toBe(false);
  });

  it('blocks verified in safeMode', () => {
    expect(canIndexRecord('verified', 'safeMode')).toBe(false);
  });

  it('blocks verified in safeModeRecommended', () => {
    expect(canIndexRecord('verified', 'safeModeRecommended')).toBe(false);
  });

  it.each([
    'quarantinedTampered',
    'quarantinedUnknownAuthor',
    'quarantinedMissingWithoutDelete',
    'quarantinedUnreadable',
    'quarantinedInvalidSchema',
  ] as RecordSecurityState[])('blocks %s in normal mode', (state) => {
    expect(canIndexRecord(state, 'normal')).toBe(false);
  });

  it('blocks pendingVerification in normal mode', () => {
    expect(canIndexRecord('pendingVerification', 'normal')).toBe(false);
  });

  it('blocks conflict in normal mode', () => {
    expect(canIndexRecord('conflict', 'normal')).toBe(false);
  });

  it('blocks containerQuarantined in normal mode', () => {
    expect(canIndexRecord('containerQuarantined', 'normal')).toBe(false);
  });

  it('blocks deletedByTrustedDevice in normal mode', () => {
    expect(canIndexRecord('deletedByTrustedDevice', 'normal')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Clipboard gate
// ---------------------------------------------------------------------------

describe('canCopyRecordSecret', () => {
  it('allows verified in normal mode', () => {
    expect(canCopyRecordSecret('verified', 'normal')).toBe(true);
  });

  it('allows verified in restricted mode', () => {
    expect(canCopyRecordSecret('verified', 'restricted')).toBe(true);
  });

  it('allows restoredFromSnapshot in normal mode', () => {
    expect(canCopyRecordSecret('restoredFromSnapshot', 'normal')).toBe(true);
  });

  it('blocks verified in lockedCritical mode', () => {
    expect(canCopyRecordSecret('verified', 'lockedCritical')).toBe(false);
  });

  it('blocks verified in safeMode', () => {
    expect(canCopyRecordSecret('verified', 'safeMode')).toBe(false);
  });

  it.each([
    'quarantinedTampered',
    'quarantinedUnknownAuthor',
    'quarantinedMissingWithoutDelete',
    'quarantinedUnreadable',
    'quarantinedInvalidSchema',
  ] as RecordSecurityState[])('blocks %s in normal mode', (state) => {
    expect(canCopyRecordSecret(state, 'normal')).toBe(false);
  });

  it('blocks pendingVerification in normal mode', () => {
    expect(canCopyRecordSecret('pendingVerification', 'normal')).toBe(false);
  });

  it('blocks conflict in normal mode', () => {
    expect(canCopyRecordSecret('conflict', 'normal')).toBe(false);
  });

  it('blocks containerQuarantined in normal mode', () => {
    expect(canCopyRecordSecret('containerQuarantined', 'normal')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Autofill gate — permanently disabled
// ---------------------------------------------------------------------------

describe('canUseRecordForAutofill', () => {
  it.each([
    'verified',
    'restoredFromSnapshot',
    'pendingVerification',
    'conflict',
    'quarantinedTampered',
    'quarantinedUnknownAuthor',
    'quarantinedMissingWithoutDelete',
    'quarantinedUnreadable',
    'quarantinedInvalidSchema',
    'containerQuarantined',
    'deletedByTrustedDevice',
  ] as RecordSecurityState[])('always denies %s in normal mode', (state) => {
    expect(canUseRecordForAutofill(state, 'normal')).toBe(false);
  });

  it.each([
    'normal',
    'restricted',
    'safeMode',
    'safeModeRecommended',
    'lockedCritical',
  ] as VaultSecurityMode[])('always denies verified in %s mode', (mode) => {
    expect(canUseRecordForAutofill('verified', mode)).toBe(false);
  });

  it('always returns false even for the most permissive combination', () => {
    expect(canUseRecordForAutofill('verified', 'normal')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// UI bridge: buildExcludedItemIdsFromOpLogView
// ---------------------------------------------------------------------------

function makeOpLogView(overrides: {
  vaultSecurityMode?: VaultSecurityMode;
  verifiedItems?: { recordId: string; recordType: string; recordVersion: number }[];
  quarantinedItems?: { recordId: string; recordState: 'quarantinedTampered'; reason: string }[];
  conflictedItems?: { recordId: string; operationCount: number; operationIds: string[] }[];
  deletedItemIds?: string[];
} = {}): VaultOpLogUiView {
  return {
    vaultSecurityMode: overrides.vaultSecurityMode ?? 'normal',
    verifiedItems: overrides.verifiedItems ?? [],
    quarantinedItems: overrides.quarantinedItems ?? [],
    conflictedItems: overrides.conflictedItems ?? [],
    deletedItemIds: overrides.deletedItemIds ?? [],
    restoredItemIds: [],
  };
}

describe('buildExcludedItemIdsFromOpLogView', () => {
  it('returns null when opLogUiView is null', () => {
    expect(buildExcludedItemIdsFromOpLogView(null)).toBeNull();
  });

  it('returns empty set when view has no quarantined/conflicted/deleted items', () => {
    const view = makeOpLogView({
      verifiedItems: [{ recordId: 'item-1', recordType: 'item', recordVersion: 1 }],
    });
    const result = buildExcludedItemIdsFromOpLogView(view);
    expect(result).toBeInstanceOf(Set);
    expect(result!.size).toBe(0);
  });

  it('collects quarantined record IDs', () => {
    const view = makeOpLogView({
      quarantinedItems: [
        { recordId: 'q-1', recordState: 'quarantinedTampered', reason: 'sig' },
        { recordId: 'q-2', recordState: 'quarantinedTampered', reason: 'hash' },
      ],
    });
    const result = buildExcludedItemIdsFromOpLogView(view)!;
    expect(result.has('q-1')).toBe(true);
    expect(result.has('q-2')).toBe(true);
    expect(result.size).toBe(2);
  });

  it('collects conflicted record IDs', () => {
    const view = makeOpLogView({
      conflictedItems: [
        { recordId: 'c-1', operationCount: 2, operationIds: ['a', 'b'] },
      ],
    });
    const result = buildExcludedItemIdsFromOpLogView(view)!;
    expect(result.has('c-1')).toBe(true);
  });

  it('collects deleted item IDs', () => {
    const view = makeOpLogView({
      deletedItemIds: ['d-1', 'd-2'],
    });
    const result = buildExcludedItemIdsFromOpLogView(view)!;
    expect(result.has('d-1')).toBe(true);
    expect(result.has('d-2')).toBe(true);
  });

  it('collects all categories in one set', () => {
    const view = makeOpLogView({
      quarantinedItems: [{ recordId: 'q-1', recordState: 'quarantinedTampered', reason: 'x' }],
      conflictedItems: [{ recordId: 'c-1', operationCount: 1, operationIds: ['a'] }],
      deletedItemIds: ['d-1'],
    });
    const result = buildExcludedItemIdsFromOpLogView(view)!;
    expect(result.size).toBe(3);
    expect(result.has('q-1')).toBe(true);
    expect(result.has('c-1')).toBe(true);
    expect(result.has('d-1')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// UI bridge: getVerifiedRecordIdsForEgress
// ---------------------------------------------------------------------------

describe('getVerifiedRecordIdsForEgress', () => {
  it('returns null when opLogUiView is null', () => {
    expect(getVerifiedRecordIdsForEgress(null)).toBeNull();
  });

  it('returns empty set when vault mode is lockedCritical', () => {
    const view = makeOpLogView({
      vaultSecurityMode: 'lockedCritical',
      verifiedItems: [{ recordId: 'item-1', recordType: 'item', recordVersion: 1 }],
    });
    const result = getVerifiedRecordIdsForEgress(view);
    expect(result).toBeInstanceOf(Set);
    expect(result!.size).toBe(0);
  });

  it('returns empty set when vault mode is safeMode', () => {
    const view = makeOpLogView({
      vaultSecurityMode: 'safeMode',
      verifiedItems: [{ recordId: 'item-1', recordType: 'item', recordVersion: 1 }],
    });
    const result = getVerifiedRecordIdsForEgress(view);
    expect(result!.size).toBe(0);
  });

  it('returns empty set when vault mode is safeModeRecommended', () => {
    const view = makeOpLogView({
      vaultSecurityMode: 'safeModeRecommended',
      verifiedItems: [{ recordId: 'item-1', recordType: 'item', recordVersion: 1 }],
    });
    const result = getVerifiedRecordIdsForEgress(view);
    expect(result!.size).toBe(0);
  });

  it('returns verified item IDs in normal mode', () => {
    const view = makeOpLogView({
      vaultSecurityMode: 'normal',
      verifiedItems: [
        { recordId: 'v-1', recordType: 'item', recordVersion: 1 },
        { recordId: 'v-2', recordType: 'item', recordVersion: 2 },
      ],
    });
    const result = getVerifiedRecordIdsForEgress(view)!;
    expect(result.size).toBe(2);
    expect(result.has('v-1')).toBe(true);
    expect(result.has('v-2')).toBe(true);
  });

  it('returns verified item IDs in restricted mode', () => {
    const view = makeOpLogView({
      vaultSecurityMode: 'restricted',
      verifiedItems: [{ recordId: 'v-1', recordType: 'item', recordVersion: 1 }],
    });
    const result = getVerifiedRecordIdsForEgress(view)!;
    expect(result.has('v-1')).toBe(true);
  });
});
