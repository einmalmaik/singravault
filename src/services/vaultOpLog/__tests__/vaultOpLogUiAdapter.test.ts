// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import {
  buildVaultOpLogUiView,
  getRecordSecurityStateUiLabel,
  getVaultSecurityModeUiLabel,
} from '../vaultOpLogUiAdapter';
import type { LocalVaultState } from '../vaultStateMachine';

describe('vaultOpLogUiAdapter', () => {
  describe('getRecordSecurityStateUiLabel', () => {
    it.each([
      ['verified', 'verified'],
      ['pendingVerification', 'pendingVerification'],
      ['conflict', 'conflict'],
      ['quarantinedTampered', 'quarantinedTampered'],
      ['quarantinedUnknownAuthor', 'quarantinedUnknownAuthor'],
      ['quarantinedMissingWithoutDelete', 'quarantinedMissingWithoutDelete'],
      ['quarantinedUnreadable', 'quarantinedUnreadable'],
      ['quarantinedInvalidSchema', 'quarantinedInvalidSchema'],
      ['containerQuarantined', 'containerQuarantined'],
      ['deletedByTrustedDevice', 'deletedByTrustedDevice'],
      ['restoredFromSnapshot', 'restoredFromSnapshot'],
    ] as const)('returns %s for %s', (input, expected) => {
      expect(getRecordSecurityStateUiLabel(input)).toBe(expected);
    });

    it('returns unknown for unexpected state', () => {
      expect(getRecordSecurityStateUiLabel('unknown_state' as unknown as 'verified')).toBe('unknown');
    });
  });

  describe('getVaultSecurityModeUiLabel', () => {
    it.each([
      ['normal', 'normal'],
      ['restricted', 'restricted'],
      ['safeMode', 'safeMode'],
      ['safeModeRecommended', 'safeModeRecommended'],
      ['lockedCritical', 'lockedCritical'],
    ] as const)('returns %s for %s', (input, expected) => {
      expect(getVaultSecurityModeUiLabel(input)).toBe(expected);
    });

    it('returns unknown for unexpected mode', () => {
      expect(getVaultSecurityModeUiLabel('unknown_mode' as unknown as 'normal')).toBe('unknown');
    });
  });

  describe('buildVaultOpLogUiView', () => {
    it('returns normal mode with no items for empty state', () => {
      const state: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('normal');
      expect(view.verifiedItems).toHaveLength(0);
      expect(view.quarantinedItems).toHaveLength(0);
      expect(view.conflictedItems).toHaveLength(0);
      expect(view.deletedItemIds).toHaveLength(0);
      expect(view.restoredItemIds).toHaveLength(0);
    });

    it('exposes only currently trusted device ids', () => {
      const state: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map([
          ['trusted-device', {
            vaultId: 'vault-1',
            deviceId: 'trusted-device',
            publicSigningKey: 'trusted-key',
            deviceNameEncrypted: '',
            addedByDeviceId: null,
            addedAt: '2026-05-11T10:00:00.000Z',
            trustEpoch: 0,
            status: 'trusted',
            revokedAt: null,
            revokedByDeviceId: null,
          }],
          ['revoked-device', {
            vaultId: 'vault-1',
            deviceId: 'revoked-device',
            publicSigningKey: 'revoked-key',
            deviceNameEncrypted: '',
            addedByDeviceId: null,
            addedAt: '2026-05-11T10:00:00.000Z',
            trustEpoch: 1,
            status: 'revoked',
            revokedAt: '2026-05-11T11:00:00.000Z',
            revokedByDeviceId: 'trusted-device',
          }],
        ]),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.trustedDeviceIds).toEqual(['trusted-device']);
    });

    it('places verified records in verifiedItems', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'verified', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('normal');
      expect(view.verifiedItems).toHaveLength(1);
      expect(view.verifiedItems[0].recordId).toBe('item-1');
      expect(view.verifiedItems[0].recordType).toBe('item');
    });

    it('places quarantinedTampered records in quarantinedItems without plaintext', () => {
      const state: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'quarantinedTampered', reason: 'tampered' }],
        ]),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('restricted');
      expect(view.quarantinedItems).toHaveLength(1);
      expect(view.quarantinedItems[0].recordId).toBe('item-1');
      expect(view.quarantinedItems[0].recordState).toBe('quarantinedTampered');
      // No plaintext should be present
      expect(view.quarantinedItems[0]).not.toHaveProperty('plaintext');
      expect(view.quarantinedItems[0]).not.toHaveProperty('decryptedData');
    });

    it('places containerQuarantined records in quarantinedItems', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'containerQuarantined', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.quarantinedItems).toHaveLength(1);
      expect(view.quarantinedItems[0].recordState).toBe('containerQuarantined');
    });

    it('places conflicts in conflictedItems and not in quarantinedItems', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'verified', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map([
          ['item-1', { recordId: 'item-1', operations: [{ opId: 'op-1' }, { opId: 'op-2' }] as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow[], recordVersions: [] }],
        ]),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('restricted');
      expect(view.conflictedItems).toHaveLength(1);
      expect(view.conflictedItems[0].recordId).toBe('item-1');
      expect(view.conflictedItems[0].operationCount).toBe(2);
      // Conflicts should not appear in quarantinedItems
      expect(view.quarantinedItems).toHaveLength(0);
    });

    it('tracks deletedByTrustedDevice in deletedItemIds', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'deletedByTrustedDevice', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.deletedItemIds).toContain('item-1');
      expect(view.verifiedItems).toHaveLength(0);
      expect(view.quarantinedItems).toHaveLength(0);
    });

    it('tracks restoredFromSnapshot in restoredItemIds and verifiedItems', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'restoredFromSnapshot', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.restoredItemIds).toContain('item-1');
      expect(view.verifiedItems).toHaveLength(1);
      expect(view.verifiedItems[0].recordId).toBe('item-1');
    });

    it('does not expose pendingVerification records in any list', () => {
      const state: LocalVaultState = {
        recordsById: new Map([
          ['item-1', { record: { recordId: 'item-1', recordType: 'item', recordVersion: 1 } as unknown as import('../vaultOpLogRpcTypes').VaultRecordRow, recordState: 'pendingVerification', plaintext: new Uint8Array(), lastOperation: { opId: 'op-1' } as unknown as import('../vaultOpLogRpcTypes').VaultOperationRow }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.verifiedItems).toHaveLength(0);
      expect(view.quarantinedItems).toHaveLength(0);
      expect(view.conflictedItems).toHaveLength(0);
      expect(view.deletedItemIds).toHaveLength(0);
    });

    it('returns safeModeRecommended when many missingWithoutDelete records exist', () => {
      const state: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map([
          ['item-1', { record: null, recordState: 'quarantinedMissingWithoutDelete' as const, reason: 'missing' }],
          ['item-2', { record: null, recordState: 'quarantinedMissingWithoutDelete' as const, reason: 'missing' }],
          ['item-3', { record: null, recordState: 'quarantinedMissingWithoutDelete' as const, reason: 'missing' }],
        ]),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('safeModeRecommended');
    });

    it('returns safeModeRecommended when 5+ quarantined records exist', () => {
      const state: LocalVaultState = {
        recordsById: new Map(),
        quarantinedRecordsById: new Map([
          ['item-1', { record: null, recordState: 'quarantinedTampered' as const, reason: 'tampered' }],
          ['item-2', { record: null, recordState: 'quarantinedTampered' as const, reason: 'tampered' }],
          ['item-3', { record: null, recordState: 'quarantinedTampered' as const, reason: 'tampered' }],
          ['item-4', { record: null, recordState: 'quarantinedTampered' as const, reason: 'tampered' }],
          ['item-5', { record: null, recordState: 'quarantinedTampered' as const, reason: 'tampered' }],
        ]),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: null,
      };

      const view = buildVaultOpLogUiView(state);

      expect(view.vaultSecurityMode).toBe('safeModeRecommended');
    });
  });
});
