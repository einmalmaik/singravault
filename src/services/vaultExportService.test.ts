import { describe, expect, it, vi } from 'vitest';

import {
  buildVaultOpLogExportPayload,
  importVaultExportPayload,
  parseVaultImportPayload,
  VaultExportBlockedError,
  VaultImportPayloadError,
} from './vaultExportService';
import type { VaultOpLogUiView } from './vaultOpLog/vaultOpLogUiAdapter';
import type { VaultOperationRow, VaultRecordRow } from './vaultOpLog/vaultOpLogRpcTypes';
import type { LocalVaultState, LocalVerifiedRecord } from './vaultOpLog/vaultStateMachine';

const textEncoder = new TextEncoder();

function makeRecord(
  recordId: string,
  recordType: VaultRecordRow['recordType'],
  plaintext: Record<string, unknown>,
  recordState: LocalVerifiedRecord['recordState'] = 'verified',
): LocalVerifiedRecord {
  const now = '2026-05-30T12:00:00.000Z';
  return {
    record: {
      vaultId: 'vault-1',
      recordId,
      recordType,
      recordVersion: 1,
      keyVersion: 1,
      aadHash: 'aad',
      ciphertextHash: `cipher-${recordId}`,
      nonce: 'nonce',
      ciphertext: 'ciphertext',
      lastOpId: `op-${recordId}`,
      lastOpHash: `hash-${recordId}`,
      isTombstone: false,
      createdAt: now,
      updatedAt: now,
    },
    recordState,
    plaintext: textEncoder.encode(JSON.stringify(plaintext)),
    lastOperation: {
      opId: `op-${recordId}`,
      opHash: `hash-${recordId}`,
      vaultId: 'vault-1',
      authorDeviceId: 'device-1',
      opType: 'create',
      recordId,
      recordType,
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: `cipher-${recordId}`,
      baseVaultHead: null,
      resultingVaultHead: 'head-1',
      intentId: null,
      rebasedFromOpId: null,
      payloadCiphertextHash: null,
      payloadAadHash: null,
      signedBody: {},
      signature: 'sig',
      signatureSchema: 'v1',
      trustEpoch: 1,
      createdAtClient: now,
      receivedAtServer: now,
      sequenceNumber: 1,
    } satisfies VaultOperationRow,
  };
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

function makeView(overrides: Partial<VaultOpLogUiView> = {}): VaultOpLogUiView {
  return {
    vaultSecurityMode: 'normal',
    verifiedItems: [],
    quarantinedItems: [],
    conflictedItems: [],
    deletedItemIds: [],
    restoredItemIds: [],
    trustedDeviceIds: [],
    ...overrides,
  };
}

describe('buildVaultOpLogExportPayload', () => {
  it('exports verified OpLog items and categories as plaintext JSON payloads', () => {
    const category = makeRecord('category-1', 'category', {
      name: 'Arbeit',
      icon: 'briefcase',
      color: '#3b82f6',
      sortOrder: 7,
    });
    const item = makeRecord('item-1', 'item', {
      title: 'GitHub',
      websiteUrl: 'https://github.com',
      username: 'octo',
      password: 'synthetic-test-secret-not-real',
      notes: 'synthetic note',
      itemType: 'totp',
      categoryRecordId: 'category-1',
      isFavorite: true,
      sortOrder: 3,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpIssuer: 'GitHub',
      totpLabel: 'octo',
      totpAlgorithm: 'SHA256',
      totpDigits: 8,
      totpPeriod: 45,
      customFields: { env: 'test' },
    });

    const payload = buildVaultOpLogExportPayload(
      makeState([category, item]),
      makeView({
        verifiedItems: [
          { recordId: 'category-1', recordType: 'category', recordVersion: 1 },
          { recordId: 'item-1', recordType: 'item', recordVersion: 1 },
        ],
      }),
    );

    expect(payload.version).toBe('1.2');
    expect(payload.categoryCount).toBe(1);
    expect(payload.itemCount).toBe(1);
    expect(payload.categories).toEqual([{
      id: 'category-1',
      name: 'Arbeit',
      icon: 'briefcase',
      color: '#3b82f6',
      sortOrder: 7,
    }]);
    expect(payload.items[0]).toMatchObject({
      id: 'item-1',
      title: 'GitHub',
      item_type: 'totp',
      category_id: 'category-1',
      sortOrder: 3,
      data: {
        title: 'GitHub',
        websiteUrl: 'https://github.com',
        username: 'octo',
        password: 'synthetic-test-secret-not-real',
        notes: 'synthetic note',
        itemType: 'totp',
        categoryId: 'category-1',
        isFavorite: true,
        totpSecret: 'JBSWY3DPEHPK3PXP',
        totpIssuer: 'GitHub',
        totpLabel: 'octo',
        totpAlgorithm: 'SHA256',
        totpDigits: 8,
        totpPeriod: 45,
        customFields: { env: 'test' },
      },
    });
  });

  it('blocks export when the vault security mode blocks egress', () => {
    expect(() => buildVaultOpLogExportPayload(
      makeState([]),
      makeView({ vaultSecurityMode: 'safeMode' }),
    )).toThrow(VaultExportBlockedError);
  });

  it('excludes records that are not verified for egress', () => {
    const verified = makeRecord('item-1', 'item', { title: 'Allowed', itemType: 'password' });
    const quarantined = makeRecord('item-2', 'item', { title: 'Blocked', itemType: 'password' });

    const payload = buildVaultOpLogExportPayload(
      makeState([verified, quarantined]),
      makeView({
        verifiedItems: [{ recordId: 'item-1', recordType: 'item', recordVersion: 1 }],
        quarantinedItems: [{
          recordId: 'item-2',
          recordState: 'quarantinedTampered',
          reason: 'tampered',
        }],
      }),
    );

    expect(payload.items.map((item) => item.id)).toEqual(['item-1']);
  });
});

describe('importVaultExportPayload', () => {
  it('imports categories first and remaps exported category IDs to new OpLog record IDs', async () => {
    const createCategory = vi.fn().mockResolvedValue({ error: null, recordId: 'new-category-1' });
    const createItem = vi.fn().mockResolvedValue({ error: null, recordId: 'new-item-1' });
    const payload = parseVaultImportPayload(JSON.stringify({
      version: '1.2',
      exportedAt: '2026-05-30T12:00:00.000Z',
      itemCount: 1,
      categoryCount: 1,
      quarantinedItems: [],
      categories: [{
        id: 'old-category-1',
        name: 'Arbeit',
        icon: 'briefcase',
        color: '#3b82f6',
        sortOrder: 1,
      }],
      items: [{
        id: 'old-item-1',
        title: 'Authenticator',
        website_url: null,
        item_type: 'totp',
        is_favorite: true,
        category_id: 'old-category-1',
        sortOrder: 2,
        data: {
          title: 'Authenticator',
          itemType: 'totp',
          isFavorite: true,
          categoryId: 'old-category-1',
          totpSecret: 'JBSWY3DPEHPK3PXP',
          totpIssuer: 'Example',
          totpLabel: 'user@example.invalid',
          totpAlgorithm: 'SHA1',
          totpDigits: 6,
          totpPeriod: 30,
          customFields: { note: 'synthetic' },
        },
      }],
    }));

    const result = await importVaultExportPayload(payload, { createCategory, createItem });

    expect(result).toEqual({ itemCount: 1, categoryCount: 1 });
    expect(createCategory).toHaveBeenCalledWith({
      name: 'Arbeit',
      icon: 'briefcase',
      color: '#3b82f6',
      parentCategoryRecordId: null,
      sortOrder: 1,
    });
    expect(createItem).toHaveBeenCalledWith({
      title: 'Authenticator',
      websiteUrl: null,
      username: null,
      password: null,
      notes: null,
      itemType: 'totp',
      categoryRecordId: 'new-category-1',
      isFavorite: true,
      sortOrder: 2,
      totpSecret: 'JBSWY3DPEHPK3PXP',
      totpIssuer: 'Example',
      totpLabel: 'user@example.invalid',
      totpAlgorithm: 'SHA1',
      totpDigits: 6,
      totpPeriod: 30,
      customFields: { note: 'synthetic' },
    });
  });

  it('rejects malformed import JSON before creating records', async () => {
    expect(() => parseVaultImportPayload('not-json')).toThrow(VaultImportPayloadError);
  });

  it('validates the full import payload before the first write', async () => {
    const createCategory = vi.fn().mockResolvedValue({ error: null, recordId: 'new-category-1' });
    const createItem = vi.fn().mockResolvedValue({ error: null, recordId: 'new-item-1' });
    const payload = parseVaultImportPayload(JSON.stringify({
      version: '1.2',
      exportedAt: '2026-05-30T12:00:00.000Z',
      itemCount: 1,
      quarantinedItems: [],
      categories: [{ id: 'old-category-1', name: 'Arbeit' }],
      items: [{
        id: 'old-item-1',
        item_type: 'password',
        is_favorite: false,
        category_id: 'old-category-1',
        data: { itemType: 'password' },
      }],
    }));

    await expect(importVaultExportPayload(payload, { createCategory, createItem }))
      .rejects.toThrow(VaultImportPayloadError);
    expect(createCategory).not.toHaveBeenCalled();
    expect(createItem).not.toHaveBeenCalled();
  });

  it('rejects malformed typed item fields instead of silently dropping data', async () => {
    const createCategory = vi.fn().mockResolvedValue({ error: null, recordId: 'new-category-1' });
    const createItem = vi.fn().mockResolvedValue({ error: null, recordId: 'new-item-1' });
    const payload = parseVaultImportPayload(JSON.stringify({
      version: '1.2',
      exportedAt: '2026-05-30T12:00:00.000Z',
      itemCount: 1,
      quarantinedItems: [],
      items: [{
        id: 'old-item-1',
        title: 'Authenticator',
        item_type: 'totp',
        is_favorite: false,
        category_id: null,
        data: {
          title: 'Authenticator',
          itemType: 'totp',
          totpSecret: 'JBSWY3DPEHPK3PXP',
          totpDigits: 10,
        },
      }],
    }));

    await expect(importVaultExportPayload(payload, { createCategory, createItem }))
      .rejects.toThrow(VaultImportPayloadError);
    expect(createCategory).not.toHaveBeenCalled();
    expect(createItem).not.toHaveBeenCalled();
  });
});
