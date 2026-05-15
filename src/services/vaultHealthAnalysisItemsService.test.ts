import { describe, expect, it, vi } from 'vitest';

import {
  buildVaultHealthSidebarSummaryInput,
  getVaultHealthAnalysisItemsFromLegacySnapshot,
  getVaultHealthAnalysisItemsFromOpLog,
  loadVaultHealthAnalysisItems,
} from './vaultHealthAnalysisItemsService';
import type { LocalVaultState, LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type { VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';

function makeRecord(
  recordId: string,
  recordType: 'item' | 'category',
  plaintext: Record<string, unknown> | null,
  recordState: LocalVerifiedRecord['recordState'] = 'verified',
): LocalVerifiedRecord {
  return {
    record: {
      vaultId: 'vault-1',
      recordId,
      recordType,
      recordVersion: 1,
      keyVersion: 1,
      aadHash: 'aad',
      ciphertextHash: 'ciphertext-hash',
      nonce: 'nonce',
      ciphertext: 'ciphertext',
      lastOpId: 'op-1',
      lastOpHash: 'op-hash',
      isTombstone: false,
      createdAt: '2026-02-18T10:00:00.000Z',
      updatedAt: '2026-02-18T12:00:00.000Z',
    },
    recordState,
    plaintext: plaintext ? new TextEncoder().encode(JSON.stringify(plaintext)) : null,
    lastOperation: {
      opId: 'op-1',
      opHash: 'op-hash',
      vaultId: 'vault-1',
      authorDeviceId: 'device-1',
      sequenceNumber: 1,
      opType: 'create_item',
      recordId,
      recordType,
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: null,
      baseVaultHead: null,
      resultingVaultHead: 'head-1',
      intentId: null,
      rebasedFromOpId: null,
      payload: {},
      signature: 'sig',
      createdAt: '2026-02-18T12:00:00.000Z',
    },
  } as LocalVerifiedRecord;
}

function makeState(records: LocalVerifiedRecord[]): LocalVaultState {
  return {
    recordsById: new Map(records.map((record) => [record.record.recordId, record])),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map(),
    lastVerifiedVaultHead: 'head-1',
  };
}

function makeHealthyIntegrityResult(): VaultIntegrityVerificationResult {
  return {
    valid: true,
    isFirstCheck: false,
    computedRoot: 'root',
    storedRoot: 'root',
    itemCount: 2,
    categoryCount: 0,
    mode: 'healthy',
    quarantinedItems: [],
  };
}

describe('vaultHealthAnalysisItemsService', () => {
  it('exports only verified OpLog password records as health-analysis items', () => {
    const state = makeState([
      makeRecord('weak-1', 'item', {
        title: 'Weak Login',
        itemType: 'password',
        password: '1234567',
      }),
      makeRecord('note-1', 'item', {
        title: 'Note',
        itemType: 'note',
        password: 'not-a-login-password',
      }),
      makeRecord('category-1', 'category', { name: 'Work' }),
      makeRecord('deleted-1', 'item', {
        title: 'Deleted',
        itemType: 'password',
        password: '1234567',
      }, 'deletedByTrustedDevice'),
      makeRecord('weak-2', 'item', {
        title: 'Second Weak Login',
        password: 'abcdefg',
      }, 'restoredFromSnapshot'),
    ]);

    expect(getVaultHealthAnalysisItemsFromOpLog(state)).toEqual([
      expect.objectContaining({ id: 'weak-1', title: 'Weak Login', itemType: 'password' }),
      expect.objectContaining({ id: 'weak-2', title: 'Second Weak Login', itemType: 'password' }),
    ]);
  });

  it('uses OpLog state directly in verified migration mode without legacy decrypt', async () => {
    const decryptItem = vi.fn();
    const verifyIntegrity = vi.fn();
    const state = makeState([
      makeRecord('weak-1', 'item', {
        title: 'Weak Login',
        itemType: 'password',
        password: '1234567',
      }),
    ]);

    const items = await loadVaultHealthAnalysisItems({
      userId: 'user-1',
      vaultMigrationStatus: 'verified',
      opLogLocalVaultState: state,
      decryptItem,
      verifyIntegrity,
    });

    expect(items).toHaveLength(1);
    expect(items[0]).toEqual(expect.objectContaining({ id: 'weak-1', password: '1234567' }));
    expect(decryptItem).not.toHaveBeenCalled();
    expect(verifyIntegrity).not.toHaveBeenCalled();
  });

  it('reflects edited OpLog item plaintext when building sidebar health input', () => {
    const beforeEditState = makeState([
      makeRecord('login-1', 'item', {
        title: 'First Login',
        itemType: 'password',
        password: 'SyntheticStrongSecret#2026-A',
      }),
      makeRecord('login-2', 'item', {
        title: 'Second Login',
        itemType: 'password',
        password: 'SyntheticStrongSecret#2026-B',
      }),
    ]);
    const afterEditState = makeState([
      makeRecord('login-1', 'item', {
        title: 'First Login',
        itemType: 'password',
        password: '1234567',
      }),
      makeRecord('login-2', 'item', {
        title: 'Second Login',
        itemType: 'password',
        password: '1234567',
      }),
    ]);

    const beforeEditInput = buildVaultHealthSidebarSummaryInput(
      getVaultHealthAnalysisItemsFromOpLog(beforeEditState),
    );
    const afterEditInput = buildVaultHealthSidebarSummaryInput(
      getVaultHealthAnalysisItemsFromOpLog(afterEditState),
    );

    expect(beforeEditInput.stats.weak).toBe(0);
    expect(beforeEditInput.stats.duplicate).toBe(0);
    expect(afterEditInput.stats.weak).toBe(2);
    expect(afterEditInput.stats.duplicate).toBe(2);
    expect(afterEditInput.affectedItems).toBe(2);
    expect(JSON.stringify(afterEditInput)).not.toContain('1234567');
  });

  it('builds sidebar health input without exposing plaintext passwords', () => {
    const input = buildVaultHealthSidebarSummaryInput([
      {
        id: 'weak-1',
        title: 'Weak Login',
        password: '1234567',
        itemType: 'password',
        updatedAt: '2025-01-01T00:00:00.000Z',
      },
      {
        id: 'weak-2',
        title: 'Second Weak Login',
        password: '1234567',
        itemType: 'password',
        websiteUrl: 'https://example.invalid',
        updatedAt: '2025-01-01T00:00:00.000Z',
      },
      {
        id: 'strong-1',
        title: 'Strong Login',
        password: 'Zy9!Rk4#Lm2@Qv8$Tn6%Wp3&Xd',
        itemType: 'password',
        websiteUrl: 'https://other.example.invalid',
        updatedAt: new Date().toISOString(),
      },
    ]);

    expect(input).toEqual(expect.objectContaining({
      passwordItems: 3,
      affectedItems: 2,
      criticalItems: 2,
      warningItems: 2,
      stats: expect.objectContaining({
        weak: 2,
        duplicate: 2,
        old: 2,
        strong: 1,
      }),
    }));
    expect(JSON.stringify(input)).not.toContain('1234567');
    expect(JSON.stringify(input)).not.toContain('Zy9!Rk4#Lm2@Qv8$Tn6%Wp3&Xd');
  });

  it('decrypts only integrity-allowed legacy snapshot items', async () => {
    const snapshot = {
      userId: 'user-1',
      vaultId: 'vault-1',
      items: [
        {
          id: 'allowed-1',
          encrypted_data: 'encrypted-allowed',
          item_type: 'password',
          website_url: null,
          updated_at: '2026-02-18T12:00:00.000Z',
        },
        {
          id: 'quarantined-1',
          encrypted_data: 'encrypted-quarantined',
          item_type: 'password',
          website_url: null,
          updated_at: '2026-02-18T12:00:00.000Z',
        },
      ],
      categories: [],
      lastSyncedAt: null,
      updatedAt: '2026-02-18T12:00:00.000Z',
    } as OfflineVaultSnapshot;
    const integrityResult = {
      ...makeHealthyIntegrityResult(),
      mode: 'quarantine',
      quarantinedItems: [{ id: 'quarantined-1', reason: 'aead_auth_failed', updatedAt: null }],
    } as VaultIntegrityVerificationResult;
    const decryptItem = vi.fn(async () => ({
      title: 'Allowed Login',
      password: '1234567',
      itemType: 'password',
    }));

    const items = await getVaultHealthAnalysisItemsFromLegacySnapshot(snapshot, integrityResult, decryptItem);

    expect(items).toEqual([
      expect.objectContaining({ id: 'allowed-1', title: 'Allowed Login', itemType: 'password' }),
    ]);
    expect(decryptItem).toHaveBeenCalledTimes(1);
    expect(decryptItem).toHaveBeenCalledWith('encrypted-allowed', 'allowed-1');
  });
});
