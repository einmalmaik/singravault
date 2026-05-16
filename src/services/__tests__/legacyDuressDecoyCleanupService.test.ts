// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockDecryptProductVaultItem = vi.fn();

vi.mock('../vaultIntegrityV2/productItemEnvelope', () => ({
  decryptProductVaultItem: (...args: unknown[]) => mockDecryptProductVaultItem(...args),
}));

interface FakeRow {
  id: string;
  encrypted_data: string;
  updated_at: string | null;
}

const fakeRows: FakeRow[] = [];
const deleteCalls: Array<{ ids: string[]; userId: string }> = [];
let deleteCountToReturn = 0;
let deleteErrorToReturn: { message: string } | null = null;

vi.mock('@/integrations/supabase/client', () => ({
  supabase: {
    from: (table: string) => {
      if (table !== 'vault_items') {
        throw new Error(`Unexpected table ${table}`);
      }
      return {
        select: () => ({
          eq: async () => ({ data: fakeRows, error: null }),
        }),
        delete: () => ({
          in: (_column: string, ids: string[]) => ({
            eq: async (_userColumn: string, userId: string) => {
              deleteCalls.push({ ids, userId });
              return { error: deleteErrorToReturn, count: deleteCountToReturn };
            },
          }),
        }),
      };
    },
  },
}));

describe('legacyDuressDecoyCleanupService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fakeRows.length = 0;
    deleteCalls.length = 0;
    deleteCountToReturn = 0;
    deleteErrorToReturn = null;
  });

  it('reports rows that fail to authenticate against the current vault key as candidates', async () => {
    const { findLegacyDuressDecoyCandidates } = await import('../legacyDuressDecoyCleanupService');

    fakeRows.push(
      { id: 'real-1', encrypted_data: 'env-real-1', updated_at: '2026-05-15T10:00:00Z' },
      { id: 'decoy-1', encrypted_data: 'env-decoy-1', updated_at: '2026-05-16T10:00:00Z' },
      { id: 'decoy-2', encrypted_data: 'env-decoy-2', updated_at: '2026-05-16T10:01:00Z' },
    );

    mockDecryptProductVaultItem.mockImplementation(async (input: { entryId: string }) => {
      if (input.entryId === 'real-1') {
        return { title: 'real' };
      }
      throw new Error('decryption failed');
    });

    const result = await findLegacyDuressDecoyCandidates({
      userId: 'user-1',
      vaultKey: { type: 'secret' } as CryptoKey,
    });

    expect(result.inspectedRowCount).toBe(3);
    expect(result.authenticatedRowCount).toBe(1);
    expect(result.candidates.map((c) => c.id)).toEqual(['decoy-1', 'decoy-2']);
    for (const candidate of result.candidates) {
      expect(candidate.reason).toBe('decryption_failed');
    }
  });

  it('never flags a row that is part of the verified OpLog working set, even if the local decrypt happens to fail', async () => {
    const { findLegacyDuressDecoyCandidates } = await import('../legacyDuressDecoyCleanupService');

    fakeRows.push(
      { id: 'oplog-record-1', encrypted_data: 'env-oplog-1', updated_at: '2026-05-15T10:00:00Z' },
      { id: 'decoy-1', encrypted_data: 'env-decoy-1', updated_at: '2026-05-16T10:00:00Z' },
    );

    // Both decrypts fail, but the OpLog set forces oplog-record-1 to be
    // treated as authenticated regardless.
    mockDecryptProductVaultItem.mockRejectedValue(new Error('boom'));

    const result = await findLegacyDuressDecoyCandidates({
      userId: 'user-1',
      vaultKey: { type: 'secret' } as CryptoKey,
      opLogVerifiedRecordIds: new Set(['oplog-record-1']),
    });

    expect(result.candidates.map((c) => c.id)).toEqual(['decoy-1']);
    expect(result.authenticatedRowCount).toBe(1);
    // We must not have called decrypt for the verified record.
    expect(mockDecryptProductVaultItem).toHaveBeenCalledTimes(1);
    expect(mockDecryptProductVaultItem.mock.calls[0]?.[0]?.entryId).toBe('decoy-1');
  });

  it('returns an empty candidate list when every row authenticates against the vault key', async () => {
    const { findLegacyDuressDecoyCandidates } = await import('../legacyDuressDecoyCleanupService');

    fakeRows.push({ id: 'real-1', encrypted_data: 'env-real-1', updated_at: null });
    mockDecryptProductVaultItem.mockResolvedValue({ title: 'real' });

    const result = await findLegacyDuressDecoyCandidates({
      userId: 'user-1',
      vaultKey: { type: 'secret' } as CryptoKey,
    });

    expect(result.candidates).toEqual([]);
    expect(result.inspectedRowCount).toBe(1);
    expect(result.authenticatedRowCount).toBe(1);
  });

  it('refuses to delete with an empty id list', async () => {
    const { purgeLegacyDuressDecoyItems } = await import('../legacyDuressDecoyCleanupService');

    await expect(
      purgeLegacyDuressDecoyItems({ userId: 'user-1', itemIds: [] }),
    ).rejects.toThrow(/empty-id-list|deactiviert/i);
    expect(deleteCalls).toEqual([]);
  });

  it('refuses to delete without a userId', async () => {
    const { purgeLegacyDuressDecoyItems } = await import('../legacyDuressDecoyCleanupService');

    await expect(
      purgeLegacyDuressDecoyItems({ userId: '', itemIds: ['decoy-1'] }),
    ).rejects.toThrow(/missing-user-id|deactiviert/i);
    expect(deleteCalls).toEqual([]);
  });

  it('deletes the requested ids scoped to user_id and returns the row count', async () => {
    const { purgeLegacyDuressDecoyItems } = await import('../legacyDuressDecoyCleanupService');

    deleteCountToReturn = 2;
    const result = await purgeLegacyDuressDecoyItems({
      userId: 'user-1',
      itemIds: ['decoy-1', 'decoy-2'],
    });

    expect(result.deletedCount).toBe(2);
    expect(deleteCalls).toEqual([
      { ids: ['decoy-1', 'decoy-2'], userId: 'user-1' },
    ]);
  });

  it('surfaces server errors verbatim', async () => {
    const { purgeLegacyDuressDecoyItems } = await import('../legacyDuressDecoyCleanupService');

    deleteErrorToReturn = { message: 'permission denied for table vault_items' };
    await expect(
      purgeLegacyDuressDecoyItems({ userId: 'user-1', itemIds: ['decoy-1'] }),
    ).rejects.toThrow(/permission denied/);
  });
});
