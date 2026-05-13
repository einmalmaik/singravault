import { describe, expect, it } from 'vitest';
import { buildVaultExportPayload } from '../vaultExportService';
import {
  assertItemDecryptable,
  VaultIntegrityDecryptBlockedError,
} from '../vaultQuarantineOrchestrator';

describe('vault quarantine decrypt guard', () => {
  it('allows healthy decrypt and non-quarantined items in quarantine mode', () => {
    expect(() => assertItemDecryptable({
      mode: 'healthy',
      quarantinedItems: [],
      itemId: 'item-1',
    })).not.toThrow();

    expect(() => assertItemDecryptable({
      mode: 'quarantine',
      quarantinedItems: [{ id: 'item-2', reason: 'item_manifest_hash_mismatch', updatedAt: null }],
      itemId: 'item-1',
    })).not.toThrow();
  });

  it('blocks quarantined items for all active V2 quarantine reasons', () => {
    expect(() => assertItemDecryptable({
      mode: 'quarantine',
      quarantinedItems: [{ id: 'item-1', reason: 'item_manifest_hash_mismatch', updatedAt: null }],
      itemId: 'item-1',
    })).toThrow('quarantined');
  });

  it.each([
    'revalidation_failed',
    'blocked',
    'integrity_unknown',
    'migration_required',
    'scope_incomplete',
    'safe',
    'future_mode',
  ])('blocks normal decrypt in %s mode even with an empty quarantine list', (mode) => {
    expect(() => assertItemDecryptable({
      mode,
      quarantinedItems: [],
      itemId: 'item-1',
    })).toThrow(VaultIntegrityDecryptBlockedError);
  });

  it('propagates integrity blocked errors out of normal exports', async () => {
    await expect(buildVaultExportPayload([
      {
        id: 'item-1',
        title: 'Item',
        website_url: null,
        item_type: 'password',
        is_favorite: null,
        category_id: null,
        encrypted_data: 'encrypted',
      },
    ], async () => {
      throw new VaultIntegrityDecryptBlockedError('revalidation_failed');
    })).rejects.toThrow(VaultIntegrityDecryptBlockedError);
  });

  it('exports only allowlisted verified items and never decrypts non-allowlisted rows', async () => {
    const decryptedIds: string[] = [];
    const payload = await buildVaultExportPayload([
      {
        id: 'item-1',
        title: 'Verified',
        website_url: null,
        item_type: 'password',
        is_favorite: null,
        category_id: null,
        encrypted_data: 'encrypted-1',
      },
      {
        id: 'item-2',
        title: 'Unknown',
        website_url: null,
        item_type: 'password',
        is_favorite: null,
        category_id: null,
        encrypted_data: 'encrypted-2',
      },
    ], async (_encryptedData, entryId) => {
      decryptedIds.push(entryId ?? '');
      return { title: entryId, itemType: 'password' };
    }, {
      allowedItemIds: new Set(['item-1']),
    });

    expect(decryptedIds).toEqual(['item-1']);
    expect(payload.itemCount).toBe(1);
    expect(payload.items.map((item) => item.id)).toEqual(['item-1']);
  });

  it('keeps quarantined diagnostics in safe export payloads without decrypting quarantined items', async () => {
    const payload = await buildVaultExportPayload([
      {
        id: 'item-1',
        title: 'Quarantined',
        website_url: null,
        item_type: 'password',
        is_favorite: null,
        category_id: null,
        encrypted_data: 'encrypted-1',
      },
    ], async () => {
      throw new Error('quarantined rows must not be decrypted');
    }, {
      mode: 'safe',
      quarantinedItems: [{ id: 'item-1', reason: 'ciphertext_changed', updatedAt: null }],
      allowedItemIds: new Set(['item-1']),
    });

    expect(payload.itemCount).toBe(0);
    expect(payload.quarantinedItems).toEqual([
      { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null },
    ]);
  });
});
