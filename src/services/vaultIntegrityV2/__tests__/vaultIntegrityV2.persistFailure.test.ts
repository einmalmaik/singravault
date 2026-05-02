import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import {
  loadManifestPersistRetryRecord,
  removeManifestPersistRetryRecord,
  saveManifestPersistRetryRecord,
} from '../index';

const USER_ID = 'user-persist-failure';
const VAULT_ID = 'vault-persist-failure';

const serviceMocks = vi.hoisted(() => ({
  loadCurrentVaultIntegritySnapshot: vi.fn(),
  assessVaultIntegritySnapshot: vi.fn(),
  persistIntegrityBaseline: vi.fn(),
  persistTrustedMutationIntegrityBaseline: vi.fn(),
  persistTrustedRecoverySnapshot: vi.fn(),
  loadTrustedRecoverySnapshotState: vi.fn(),
  persistRuntimeManifestV2ForTrustedSnapshot: vi.fn(),
  retryPendingRuntimeManifestV2ForSnapshot: vi.fn(),
  decryptVaultItem: vi.fn(),
  warn: vi.fn(),
}));

vi.mock('@/services/offlineVaultRuntimeService', () => ({
  loadCurrentVaultIntegritySnapshot: serviceMocks.loadCurrentVaultIntegritySnapshot,
}));

vi.mock('@/services/vaultIntegrityDecisionEngine', () => ({
  assessVaultIntegritySnapshot: serviceMocks.assessVaultIntegritySnapshot,
  buildVaultIntegritySnapshot: vi.fn((snapshot: OfflineVaultSnapshot) => ({
    items: snapshot.items,
    categories: snapshot.categories,
  })),
  canRebaselineRecentLocalMutation: vi.fn(() => false),
  canRebaselineTrustedMutation: vi.fn(() => false),
  hasTrustedDrift: vi.fn(() => false),
  hasTrustedMutationScope: vi.fn(() => false),
  normalizeTrustedVaultMutation: vi.fn((mutation?: { itemIds?: Iterable<string>; categoryIds?: Iterable<string> }) => ({
    itemIds: new Set(mutation?.itemIds ?? []),
    categoryIds: new Set(mutation?.categoryIds ?? []),
  })),
}));

vi.mock('@/services/vaultIntegrityService', () => ({
  VaultIntegrityBaselineError: class VaultIntegrityBaselineError extends Error {},
  isNonTamperIntegrityMode: vi.fn((mode: string) => (
    mode === 'integrity_unknown'
    || mode === 'revalidation_failed'
    || mode === 'migration_required'
    || mode === 'scope_incomplete'
  )),
  persistIntegrityBaseline: serviceMocks.persistIntegrityBaseline,
  persistTrustedMutationIntegrityBaseline: serviceMocks.persistTrustedMutationIntegrityBaseline,
}));

vi.mock('@/services/vaultRecoveryOrchestrator', () => ({
  loadTrustedRecoverySnapshotState: serviceMocks.loadTrustedRecoverySnapshotState,
  persistTrustedRecoverySnapshot: serviceMocks.persistTrustedRecoverySnapshot,
}));

vi.mock('@/services/vaultIntegrityV2/runtimeBridge', () => ({
  evaluateRuntimeVaultIntegrityV2: vi.fn(async () => null),
  persistRuntimeManifestV2ForTrustedSnapshot: serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot,
  retryPendingRuntimeManifestV2ForSnapshot: serviceMocks.retryPendingRuntimeManifestV2ForSnapshot,
  safeManifestPersistErrorCode: vi.fn(() => 'manifest_persist_failed'),
}));

vi.mock('@/services/vaultIntegrityV2/itemEnvelopeCrypto', () => ({
  parseVaultItemEnvelopeV2: vi.fn((encryptedData: string) => {
    if (!encryptedData.startsWith('sv-vault-v2:')) {
      return { ok: false, error: 'unsupported_envelope' };
    }
    const itemId = encryptedData === 'sv-vault-v2:legacy-candidate' ? 'legacy-v2-item' : 'item-1';
    return {
      ok: true,
      envelope: {
        itemId,
        userId: USER_ID,
        vaultId: VAULT_ID,
        itemType: 'password',
        keyId: 'legacy-kdf-v1',
        itemRevision: 2,
        schemaVersion: 1,
      },
    };
  }),
  verifyAndDecryptItemEnvelopeV2: vi.fn(() => ({ ok: true, data: {}, envelope: {}, envelopeHash: 'hash' })),
}));

vi.mock('@/services/cryptoService', () => ({
  decryptVaultItem: serviceMocks.decryptVaultItem,
}));

function snapshot(): OfflineVaultSnapshot {
  return {
    userId: USER_ID,
    vaultId: VAULT_ID,
    items: [{
      id: 'item-1',
      user_id: USER_ID,
      vault_id: VAULT_ID,
      title: '',
      website_url: null,
      icon_url: null,
      item_type: 'password',
      category_id: null,
      is_favorite: null,
      sort_order: null,
      last_used_at: null,
      encrypted_data: 'sv-vault-v2:item',
      created_at: '2026-04-30T10:00:00.000Z',
      updated_at: '2026-04-30T10:00:00.000Z',
    }],
    categories: [],
    lastSyncedAt: '2026-04-30T10:00:00.000Z',
    updatedAt: '2026-04-30T10:00:00.000Z',
  };
}

describe('Manifest V2 runtime persist failure handling', () => {
  beforeEach(async () => {
    vi.restoreAllMocks();
    Object.values(serviceMocks).forEach((mock) => {
      if (typeof mock === 'function' && 'mockReset' in mock) {
        mock.mockReset();
      }
    });
    vi.spyOn(console, 'warn').mockImplementation(serviceMocks.warn);
    await removeManifestPersistRetryRecord(USER_ID, VAULT_ID).catch(() => undefined);

    const rawSnapshot = snapshot();
    serviceMocks.loadCurrentVaultIntegritySnapshot.mockResolvedValue({
      rawSnapshot,
      integritySnapshot: {
        items: rawSnapshot.items.map((item) => ({ id: item.id, encrypted_data: item.encrypted_data })),
        categories: [],
      },
      source: 'remote',
    });
    serviceMocks.assessVaultIntegritySnapshot.mockResolvedValue({
      unreadableCategoryReason: null,
      inspection: {
        digest: 'digest-after-v1-write',
        itemCount: 1,
        categoryCount: 0,
        baselineKind: 'v2',
        storedRoot: 'old-digest',
        legacyBaselineMismatch: false,
        itemDrifts: [],
        categoryDriftIds: [],
      },
      result: {
        valid: true,
        isFirstCheck: false,
        computedRoot: 'digest-after-v1-write',
        storedRoot: 'old-digest',
        itemCount: 1,
        categoryCount: 0,
        mode: 'healthy',
        quarantinedItems: [],
      },
    });
    serviceMocks.persistIntegrityBaseline.mockResolvedValue('digest-after-v1-write');
    serviceMocks.persistTrustedRecoverySnapshot.mockResolvedValue({
      trustedRecoveryAvailable: true,
      trustedSnapshotItemsById: {},
      trustedSnapshot: rawSnapshot,
    });
    serviceMocks.loadTrustedRecoverySnapshotState.mockResolvedValue({
      trustedRecoveryAvailable: false,
      trustedSnapshotItemsById: {},
      trustedSnapshot: null,
    });
    serviceMocks.retryPendingRuntimeManifestV2ForSnapshot.mockResolvedValue({ status: 'no_pending' });
    serviceMocks.decryptVaultItem.mockResolvedValue({});
  });

  it('surfaces Manifest V2 persist failures as revalidation_failed and stores a retry record', async () => {
    const { refreshVaultIntegrityBaseline } = await import('@/services/vaultIntegrityRuntimeService');
    const callbacks = {
      applyIntegrityResultState: vi.fn(),
      applyTrustedRecoveryState: vi.fn(),
      setBlockedIntegrityState: vi.fn(),
      bumpVaultDataVersion: vi.fn(),
    };
    serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot.mockRejectedValue(
      new Error('secret token should not be logged'),
    );

    await refreshVaultIntegrityBaseline({
      userId: USER_ID,
      encryptionKey: {} as CryptoKey,
      callbacks,
    });

    expect(callbacks.applyIntegrityResultState).toHaveBeenLastCalledWith(expect.objectContaining({
      mode: 'revalidation_failed',
      nonTamperReason: 'manifest_persist_failed',
      quarantinedItems: [],
    }));
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toMatchObject({
      snapshotDigest: 'digest-after-v1-write',
      lastErrorCode: 'manifest_persist_failed',
    });
    expect(JSON.stringify(serviceMocks.warn.mock.calls)).not.toContain('secret token');
  });

  it('clears a stale pending manifest retry record on snapshot mismatch so baseline refresh can proceed', async () => {
    const { refreshVaultIntegrityBaseline } = await import('@/services/vaultIntegrityRuntimeService');
    const callbacks = {
      applyIntegrityResultState: vi.fn(),
      applyTrustedRecoveryState: vi.fn(),
      setBlockedIntegrityState: vi.fn(),
      bumpVaultDataVersion: vi.fn(),
    };
    await saveManifestPersistRetryRecord({
      userId: USER_ID,
      vaultId: VAULT_ID,
      snapshotDigest: 'stale-digest-for-mismatch',
      lastErrorCode: 'manifest_persist_failed',
    });
    serviceMocks.retryPendingRuntimeManifestV2ForSnapshot.mockResolvedValue({
      status: 'snapshot_mismatch',
      errorCode: 'manifest_retry_snapshot_mismatch',
    });
    serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot.mockResolvedValue('persisted');

    await refreshVaultIntegrityBaseline({
      userId: USER_ID,
      encryptionKey: {} as CryptoKey,
      callbacks,
    });

    expect(callbacks.applyIntegrityResultState).toHaveBeenLastCalledWith(expect.objectContaining({
      mode: 'healthy',
    }));
    await expect(loadManifestPersistRetryRecord(USER_ID, VAULT_ID)).resolves.toBeNull();
  });

  it('lets an explicit remote refresh bootstrap Manifest V2 after authenticated V2 ciphertext drift', async () => {
    const { refreshVaultIntegrityBaseline } = await import('@/services/vaultIntegrityRuntimeService');
    const callbacks = {
      applyIntegrityResultState: vi.fn(),
      applyTrustedRecoveryState: vi.fn(),
      setBlockedIntegrityState: vi.fn(),
      bumpVaultDataVersion: vi.fn(),
    };
    serviceMocks.assessVaultIntegritySnapshot.mockResolvedValue({
      unreadableCategoryReason: null,
      inspection: {
        digest: 'digest-after-manual-bootstrap',
        itemCount: 1,
        categoryCount: 0,
        baselineKind: 'v2',
        storedRoot: 'old-digest',
        legacyBaselineMismatch: false,
        itemDrifts: [
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: '2026-04-30T10:00:00.000Z' },
          { id: 'deleted-item', reason: 'missing_on_server', updatedAt: null },
        ],
        categoryDriftIds: [],
      },
      result: {
        valid: true,
        isFirstCheck: false,
        computedRoot: 'digest-after-manual-bootstrap',
        storedRoot: 'old-digest',
        itemCount: 1,
        categoryCount: 0,
        mode: 'quarantine',
        quarantinedItems: [
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: '2026-04-30T10:00:00.000Z' },
        ],
      },
    });
    serviceMocks.persistIntegrityBaseline.mockResolvedValue('digest-after-manual-bootstrap');
    serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot.mockResolvedValue('persisted');

    const result = await refreshVaultIntegrityBaseline({
      userId: USER_ID,
      encryptionKey: {} as CryptoKey,
      callbacks,
    });

    expect(result).toMatchObject({ mode: 'healthy' });
    expect(serviceMocks.persistIntegrityBaseline).toHaveBeenCalledWith(
      USER_ID,
      expect.anything(),
      expect.anything(),
      'digest-after-manual-bootstrap',
      { vaultId: VAULT_ID },
    );
    expect(serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot).toHaveBeenCalled();
    expect(callbacks.applyIntegrityResultState).toHaveBeenLastCalledWith(expect.objectContaining({
      mode: 'healthy',
    }));
  });

  it('lets an explicit remote refresh bootstrap a mixed V2/V1 snapshot after every current item authenticates', async () => {
    const { refreshVaultIntegrityBaseline } = await import('@/services/vaultIntegrityRuntimeService');
    const callbacks = {
      applyIntegrityResultState: vi.fn(),
      applyTrustedRecoveryState: vi.fn(),
      setBlockedIntegrityState: vi.fn(),
      bumpVaultDataVersion: vi.fn(),
    };
    const rawSnapshot = snapshot();
    rawSnapshot.items = [
      rawSnapshot.items[0],
      {
        ...rawSnapshot.items[0],
        id: 'legacy-v1-item',
        encrypted_data: 'sv-vault-v1:legacy-item',
        created_at: '2026-04-30T11:00:00.000Z',
        updated_at: '2026-04-30T11:00:00.000Z',
      },
    ];
    serviceMocks.loadCurrentVaultIntegritySnapshot.mockResolvedValue({
      rawSnapshot,
      integritySnapshot: {
        items: rawSnapshot.items.map((item) => ({ id: item.id, encrypted_data: item.encrypted_data })),
        categories: [],
      },
      source: 'remote',
    });
    serviceMocks.assessVaultIntegritySnapshot.mockResolvedValue({
      unreadableCategoryReason: null,
      inspection: {
        digest: 'digest-after-mixed-manual-bootstrap',
        itemCount: 2,
        categoryCount: 0,
        baselineKind: 'v2',
        storedRoot: 'old-digest',
        legacyBaselineMismatch: false,
        itemDrifts: [
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: '2026-04-30T10:00:00.000Z' },
          { id: 'legacy-v1-item', reason: 'unknown_on_server', updatedAt: '2026-04-30T11:00:00.000Z' },
          { id: 'deleted-item', reason: 'missing_on_server', updatedAt: null },
        ],
        categoryDriftIds: [],
      },
      result: {
        valid: true,
        isFirstCheck: false,
        computedRoot: 'digest-after-mixed-manual-bootstrap',
        storedRoot: 'old-digest',
        itemCount: 2,
        categoryCount: 0,
        mode: 'quarantine',
        quarantinedItems: [
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: '2026-04-30T10:00:00.000Z' },
        ],
      },
    });
    serviceMocks.persistIntegrityBaseline.mockResolvedValue('digest-after-mixed-manual-bootstrap');
    serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot.mockResolvedValue('skipped_legacy_items');

    const result = await refreshVaultIntegrityBaseline({
      userId: USER_ID,
      encryptionKey: {} as CryptoKey,
      callbacks,
    });

    expect(result).toMatchObject({ mode: 'healthy' });
    expect(serviceMocks.decryptVaultItem).toHaveBeenCalledWith(
      'sv-vault-v1:legacy-item',
      expect.anything(),
      'legacy-v1-item',
    );
    expect(serviceMocks.persistRuntimeManifestV2ForTrustedSnapshot).toHaveBeenCalled();
    expect(callbacks.applyIntegrityResultState).toHaveBeenLastCalledWith(expect.objectContaining({
      mode: 'healthy',
    }));
  });

  it('applies a visible non-healthy state when manual recheck cannot load a snapshot', async () => {
    const { verifyVaultIntegrity } = await import('@/services/vaultIntegrityRuntimeService');
    const callbacks = {
      applyIntegrityResultState: vi.fn(),
      applyTrustedRecoveryState: vi.fn(),
      setBlockedIntegrityState: vi.fn(),
      bumpVaultDataVersion: vi.fn(),
    };
    serviceMocks.loadCurrentVaultIntegritySnapshot.mockRejectedValue(new Error('fetch failed'));

    const result = await verifyVaultIntegrity({
      userId: USER_ID,
      encryptionKey: {} as CryptoKey,
      callbacks,
    });

    expect(result).toMatchObject({
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    });
    expect(callbacks.applyIntegrityResultState).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'revalidation_failed',
      nonTamperReason: 'revalidation_failed',
      quarantinedItems: [],
    }));
    expect(callbacks.setBlockedIntegrityState).not.toHaveBeenCalled();
    expect(JSON.stringify(serviceMocks.warn.mock.calls)).not.toContain('fetch failed');
  });
});
