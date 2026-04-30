import { describe, expect, it } from 'vitest';

import {
  shouldDowngradeCrossDeviceV2BaselineDrift,
} from '@/services/vaultIntegrityRuntimeService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import type { VaultIntegrityAssessment } from '@/services/vaultIntegrityDecisionEngine';
import { serializeVaultItemEnvelopeV2 } from '@/services/vaultIntegrityV2/itemEnvelopeCrypto';

function snapshotWithV2Item(): OfflineVaultSnapshot {
  return {
    userId: 'user-1',
    vaultId: 'vault-1',
    items: [{
      id: 'item-1',
      user_id: 'user-1',
      vault_id: 'vault-1',
      title: '',
      website_url: null,
      icon_url: null,
      item_type: 'password',
      category_id: null,
      is_favorite: null,
      sort_order: null,
      last_used_at: null,
      encrypted_data: serializeVaultItemEnvelopeV2({
        envelopeVersion: 2,
        vaultId: 'vault-1',
        userId: 'user-1',
        itemId: 'item-1',
        itemType: 'password',
        keyId: 'user-key-v2',
        itemRevision: 2,
        schemaVersion: 1,
        nonce: 'nonce',
        ciphertext: 'ciphertext',
        aad: {
          purpose: 'vault_item',
          envelopeVersion: 2,
          vaultId: 'vault-1',
          userId: 'user-1',
          itemId: 'item-1',
          itemType: 'password',
          keyId: 'user-key-v2',
          itemRevision: 2,
          schemaVersion: 1,
        },
      }),
      created_at: '2026-04-30T10:00:00.000Z',
      updated_at: '2026-04-30T10:05:00.000Z',
    }],
    categories: [],
    lastSyncedAt: '2026-04-30T10:05:00.000Z',
    updatedAt: '2026-04-30T10:05:00.000Z',
  };
}

function assessment(reason: 'ciphertext_changed' | 'missing_on_server'): VaultIntegrityAssessment {
  return {
    unreadableCategoryReason: null,
    inspection: {
      digest: 'digest',
      itemCount: 1,
      categoryCount: 0,
      baselineKind: 'v2',
      storedRoot: 'old-digest',
      legacyBaselineMismatch: false,
      itemDrifts: [{ id: 'item-1', reason, updatedAt: '2026-04-30T10:05:00.000Z' }],
      categoryDriftIds: [],
    },
    result: {
      valid: true,
      isFirstCheck: false,
      computedRoot: 'digest',
      storedRoot: 'old-digest',
      itemCount: 1,
      categoryCount: 0,
      mode: 'quarantine',
      quarantinedItems: [{ id: 'item-1', reason, updatedAt: '2026-04-30T10:05:00.000Z' }],
    },
  };
}

describe('vaultIntegrityRuntimeService cross-device V2 fallback', () => {
  it('downgrades remote V2 ciphertext drift without a manifest to revalidation work', () => {
    expect(shouldDowngradeCrossDeviceV2BaselineDrift({
      assessment: assessment('ciphertext_changed'),
      snapshot: snapshotWithV2Item(),
      source: 'remote',
    })).toBe(true);
  });

  it('does not downgrade non-ciphertext diagnostics or cache-only drift', () => {
    expect(shouldDowngradeCrossDeviceV2BaselineDrift({
      assessment: assessment('missing_on_server'),
      snapshot: snapshotWithV2Item(),
      source: 'remote',
    })).toBe(false);

    expect(shouldDowngradeCrossDeviceV2BaselineDrift({
      assessment: assessment('ciphertext_changed'),
      snapshot: snapshotWithV2Item(),
      source: 'cache',
    })).toBe(false);
  });
});
