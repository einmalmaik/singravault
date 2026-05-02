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
});
