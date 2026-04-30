import { beforeEach, describe, expect, it, vi } from 'vitest';

const supabaseState = vi.hoisted(() => ({
  upsertResult: null as Record<string, unknown> | null,
  upsertError: null as Error | null,
  deleteResult: [{ id: 'item-1' }] as Array<Record<string, unknown>>,
  deleteError: null as Error | null,
  lookupResult: [{ id: 'item-1' }] as Array<Record<string, unknown>>,
  lookupError: null as Error | null,
  operations: [] as Array<Record<string, unknown>>,
}));

const dependencyMocks = vi.hoisted(() => ({
  enqueueOfflineMutation: vi.fn(async (_mutation: Record<string, unknown>) => 'mutation-1'),
  upsertOfflineItemRow: vi.fn(async (_userId: string, _item: Record<string, unknown>, _vaultId: string | null) => undefined),
  removeOfflineItemRow: vi.fn(async (_userId: string, _itemId: string) => undefined),
  resolveDefaultVaultId: vi.fn(async (_userId: string) => 'vault-1'),
  buildVaultItemRowFromInsert: vi.fn((payload: Record<string, unknown>) => ({
    ...payload,
    created_at: '2026-04-23T00:00:00.000Z',
    updated_at: '2026-04-23T00:00:00.000Z',
  })),
  isAppOnline: vi.fn(() => true),
  isLikelyOfflineError: vi.fn((_error: unknown) => false),
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: {
    from: (table: string) => ({
      select: () => {
        const filters: Record<string, string> = {};
        const chain = {
          eq: (column: string, value: string) => {
            filters[column] = value;
            supabaseState.operations.push({ kind: 'lookup-filter', table, column, value });
            if ('user_id' in filters && 'id' in filters) {
              return Promise.resolve({
                data: supabaseState.lookupResult,
                error: supabaseState.lookupError,
              });
            }
            return chain;
          },
        };
        return chain;
      },
      upsert: (payload: Record<string, unknown>, options: Record<string, unknown>) => {
        supabaseState.operations.push({ kind: 'upsert', table, payload, options });
        return {
          select: () => ({
            single: async () => ({
              data: supabaseState.upsertResult,
              error: supabaseState.upsertError,
            }),
          }),
        };
      },
      delete: () => ({
        select: () => {
          const filters: Record<string, string> = {};
          const chain = {
            eq: (column: string, value: string) => {
              filters[column] = value;
              supabaseState.operations.push({ kind: 'delete-filter', table, column, value });
              if ('user_id' in filters && 'id' in filters) {
                return Promise.resolve({
                  data: supabaseState.deleteResult,
                  error: supabaseState.deleteError,
                });
              }
              return chain;
            },
          };
          return chain;
        },
      }),
    }),
  },
}));

vi.mock('@/services/offlineVaultService', () => ({
  buildVaultItemRowFromInsert: (payload: Record<string, unknown>) => dependencyMocks.buildVaultItemRowFromInsert(payload),
  enqueueOfflineMutation: (mutation: Record<string, unknown>) => dependencyMocks.enqueueOfflineMutation(mutation),
  upsertOfflineItemRow: (userId: string, item: Record<string, unknown>, vaultId: string | null) =>
    dependencyMocks.upsertOfflineItemRow(userId, item, vaultId),
  removeOfflineItemRow: (userId: string, itemId: string) => dependencyMocks.removeOfflineItemRow(userId, itemId),
  resolveDefaultVaultId: (userId: string) => dependencyMocks.resolveDefaultVaultId(userId),
  isAppOnline: () => dependencyMocks.isAppOnline(),
  isLikelyOfflineError: (error: unknown) => dependencyMocks.isLikelyOfflineError(error),
}));

import {
  buildQuarantineResolutionMap,
  deleteQuarantinedItemFromVault,
  indexTrustedSnapshotItems,
  restoreQuarantinedItemFromTrustedSnapshot,
} from './vaultQuarantineRecoveryService';

describe('vaultQuarantineRecoveryService', () => {
  const trustedItem = {
    id: 'item-1',
    user_id: 'user-1',
    vault_id: 'vault-1',
    title: 'Encrypted Item',
    website_url: null,
    icon_url: null,
    item_type: 'password',
    is_favorite: false,
    encrypted_data: 'cipher-1',
    category_id: null,
    sort_order: null,
    last_used_at: null,
    created_at: '2026-04-22T00:00:00.000Z',
    updated_at: '2026-04-22T00:00:00.000Z',
  } as const;

  beforeEach(() => {
    supabaseState.upsertResult = trustedItem;
    supabaseState.upsertError = null;
    supabaseState.deleteResult = [{ id: 'item-1' }];
    supabaseState.deleteError = null;
    supabaseState.lookupResult = [{ id: 'item-1' }];
    supabaseState.lookupError = null;
    supabaseState.operations.length = 0;
    vi.clearAllMocks();
    dependencyMocks.resolveDefaultVaultId.mockResolvedValue('vault-1');
    dependencyMocks.isAppOnline.mockReturnValue(true);
    dependencyMocks.isLikelyOfflineError.mockReturnValue(false);
  });

  it('builds per-item recovery capabilities from reason and trusted snapshot', () => {
    const trustedItemsById = indexTrustedSnapshotItems({
      userId: 'user-1',
      vaultId: 'vault-1',
      items: [trustedItem],
      categories: [],
      lastSyncedAt: null,
      updatedAt: '2026-04-23T00:00:00.000Z',
    });

    const resolutions = buildQuarantineResolutionMap([
      { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null },
      { id: 'item-2', reason: 'missing_on_server', updatedAt: null },
      { id: 'item-3', reason: 'unknown_on_server', updatedAt: null },
    ], trustedItemsById, {
      'item-3': { isBusy: true, lastError: 'failed' },
    });

    expect(resolutions['item-1']).toMatchObject({
      canRestore: true,
      canDelete: true,
      canAcceptMissing: false,
      hasTrustedLocalCopy: true,
    });
    expect(resolutions['item-2']).toMatchObject({
      canRestore: false,
      canDelete: false,
      canAcceptMissing: true,
      hasTrustedLocalCopy: false,
    });
    expect(resolutions['item-3']).toMatchObject({
      canRestore: false,
      canDelete: true,
      canAcceptMissing: false,
      isBusy: true,
      lastError: 'failed',
    });
  });

  it('does not mark missing or unknown diagnostics as restorable even with stale trusted rows', () => {
    const staleTrustedRows = indexTrustedSnapshotItems({
      userId: 'user-1',
      vaultId: 'vault-1',
      items: [
        trustedItem,
        { ...trustedItem, id: 'item-missing' },
        { ...trustedItem, id: 'item-unknown' },
      ],
      categories: [],
      lastSyncedAt: null,
      updatedAt: '2026-04-23T00:00:00.000Z',
    });

    const resolutions = buildQuarantineResolutionMap([
      { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null },
      { id: 'item-missing', reason: 'missing_on_server', updatedAt: null },
      { id: 'item-unknown', reason: 'unknown_on_server', updatedAt: null },
    ], staleTrustedRows);

    expect(resolutions['item-1']).toMatchObject({
      canRestore: true,
      hasTrustedLocalCopy: true,
    });
    expect(resolutions['item-missing']).toMatchObject({
      canRestore: false,
      canAcceptMissing: true,
      hasTrustedLocalCopy: true,
    });
    expect(resolutions['item-unknown']).toMatchObject({
      canRestore: false,
      canDelete: true,
      hasTrustedLocalCopy: true,
    });
  });

  it('restores a trusted local copy through the normal online upsert path', async () => {
    const result = await restoreQuarantinedItemFromTrustedSnapshot('user-1', trustedItem);

    expect(result).toEqual({ syncedOnline: true });
    expect(supabaseState.operations).toContainEqual(
      expect.objectContaining({
        kind: 'upsert',
        table: 'vault_items',
        payload: expect.objectContaining({
          id: 'item-1',
          encrypted_data: 'cipher-1',
          vault_id: 'vault-1',
        }),
      }),
    );
    expect(dependencyMocks.upsertOfflineItemRow).toHaveBeenCalledWith(
      'user-1',
      trustedItem,
      'vault-1',
    );
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });

  it('queues an offline restore when the remote write cannot be reached', async () => {
    dependencyMocks.isAppOnline.mockReturnValue(false);

    const result = await restoreQuarantinedItemFromTrustedSnapshot('user-1', trustedItem);

    expect(result).toEqual({ syncedOnline: false });
    expect(dependencyMocks.buildVaultItemRowFromInsert).toHaveBeenCalled();
    expect(dependencyMocks.upsertOfflineItemRow).toHaveBeenCalled();
    expect(dependencyMocks.enqueueOfflineMutation).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        type: 'upsert_item',
        payload: expect.objectContaining({
          id: 'item-1',
        }),
      }),
    );
  });

  it('does not mutate local restore state when an online write fails transiently', async () => {
    dependencyMocks.isLikelyOfflineError.mockReturnValue(true);
    supabaseState.upsertError = new Error('network down');

    const result = await restoreQuarantinedItemFromTrustedSnapshot('user-1', trustedItem);

    expect(result).toEqual({ syncedOnline: false });
    expect(dependencyMocks.buildVaultItemRowFromInsert).not.toHaveBeenCalled();
    expect(dependencyMocks.upsertOfflineItemRow).not.toHaveBeenCalled();
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });

  it('deletes a quarantined item and skips queueing when the remote delete succeeds', async () => {
    const result = await deleteQuarantinedItemFromVault('user-1', 'item-1');

    expect(result).toEqual({ syncedOnline: true });
    expect(supabaseState.operations).toContainEqual(
      expect.objectContaining({
        kind: 'delete-filter',
        table: 'vault_items',
        column: 'id',
        value: 'item-1',
      }),
    );
    expect(dependencyMocks.removeOfflineItemRow).toHaveBeenCalledWith('user-1', 'item-1');
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });

  it('does not mutate local delete state when an online delete fails transiently', async () => {
    dependencyMocks.isLikelyOfflineError.mockReturnValue(true);
    supabaseState.deleteError = new Error('network down');

    const result = await deleteQuarantinedItemFromVault('user-1', 'item-1');

    expect(result).toEqual({ syncedOnline: false });
    expect(dependencyMocks.removeOfflineItemRow).not.toHaveBeenCalled();
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });

  it('treats an already missing server item as successfully deleted', async () => {
    supabaseState.deleteResult = [];
    supabaseState.lookupResult = [];

    await expect(deleteQuarantinedItemFromVault('user-1', 'item-1')).resolves.toEqual({
      syncedOnline: true,
    });
    expect(dependencyMocks.removeOfflineItemRow).toHaveBeenCalledWith('user-1', 'item-1');
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });

  it('does not rebaseline against a delete no-op while the item still exists on the server', async () => {
    supabaseState.deleteResult = [];
    supabaseState.lookupResult = [{ id: 'item-1' }];

    await expect(deleteQuarantinedItemFromVault('user-1', 'item-1')).rejects.toThrow(
      'serverseitig nicht gelöscht',
    );
    expect(dependencyMocks.removeOfflineItemRow).not.toHaveBeenCalled();
    expect(dependencyMocks.enqueueOfflineMutation).not.toHaveBeenCalled();
  });
});
