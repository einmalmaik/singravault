// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Tests for VaultItemList Component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

import { VaultItemList } from '../VaultItemList';
import { loadVaultSnapshot } from '@/services/offlineVaultService';

type SnapshotItem = {
  id: string;
  vault_id: string;
  title: string;
  website_url: string | null;
  icon_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean;
  category_id: string | null;
  created_at: string;
  updated_at: string;
  encrypted_data: string;
};

const snapshotState = vi.hoisted(() => ({
  items: [] as SnapshotItem[],
  online: false,
  source: 'remote' as 'remote' | 'cache' | 'empty',
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: string | { defaultValue?: string; count?: number }) => {
      if (typeof options === 'string') {
        return options;
      }
      if (options?.defaultValue && typeof options.count === 'number') {
        return options.defaultValue.replace('{{count}}', String(options.count));
      }
      return options?.defaultValue || key;
    },
  }),
}));

const mockDecryptItem = vi.fn();
const mockDecryptItemForLegacyMigration = vi.fn();
const mockEncryptItem = vi.fn();
const mockVerifyIntegrity = vi.fn();
const mockRefreshIntegrityBaseline = vi.fn();
const mockReportUnreadableItems = vi.fn();
const mockMigrateLegacyVaultItemEncryptionAndMetadata = vi.fn();

const MockLegacyVaultMetadataMigrationPersistenceError = vi.hoisted(() => class extends Error {
  constructor(public readonly itemId: string) {
    super(`Could not persist legacy metadata migration for item ${itemId}.`);
    this.name = 'LegacyVaultMetadataMigrationPersistenceError';
  }
});

const mockVaultContext = {
  decryptItem: (...args: unknown[]) => mockDecryptItem(...args),
  decryptItemForLegacyMigration: (...args: unknown[]) => mockDecryptItemForLegacyMigration(...args),
  encryptItem: (...args: unknown[]) => mockEncryptItem(...args),
  verifyIntegrity: (...args: unknown[]) => mockVerifyIntegrity(...args),
  refreshIntegrityBaseline: (...args: unknown[]) => mockRefreshIntegrityBaseline(...args),
  reportUnreadableItems: (...args: unknown[]) => mockReportUnreadableItems(...args),
  isDuressMode: false,
  vaultDataVersion: 0,
  quarantineResolutionById: {} as Record<string, {
    canRestore: boolean;
    canDelete: boolean;
    canAcceptMissing: boolean;
    hasTrustedLocalCopy: boolean;
    isBusy: boolean;
    lastError: string | null;
  }>,
  restoreQuarantinedItem: vi.fn(),
  deleteQuarantinedItem: vi.fn(),
  acceptMissingQuarantinedItem: vi.fn(),
  lastIntegrityResult: null as
    | null
    | {
        mode?: 'healthy' | 'quarantine' | 'blocked';
        quarantinedItems: Array<{
          id: string;
          reason: 'ciphertext_changed' | 'missing_on_server' | 'unknown_on_server' | 'decrypt_failed';
          updatedAt: string | null;
          itemType?: 'password' | 'note' | 'totp' | 'card' | null;
        }>;
      },
};
const mockUser = { id: 'user-1' };

vi.mock('@/contexts/VaultContext', () => ({
  useVault: () => mockVaultContext,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: mockUser,
  }),
}));

vi.mock('@/services/offlineVaultService', () => ({
  loadVaultSnapshot: vi.fn().mockImplementation(async () => ({
    source: snapshotState.source,
    snapshot: {
      vaultId: 'vault-1',
      categories: [],
      items: snapshotState.items,
    },
  })),
  isAppOnline: vi.fn().mockImplementation(() => snapshotState.online),
  upsertOfflineItemRow: vi.fn(),
}));

vi.mock('@/services/legacyVaultMetadataMigrationService', () => ({
  LegacyVaultMetadataMigrationPersistenceError: MockLegacyVaultMetadataMigrationPersistenceError,
  migrateLegacyVaultItemMetadata: vi.fn(async (input: { item: SnapshotItem; decryptedData: unknown }) => ({
    item: input.item,
    decryptedData: input.decryptedData,
    migrated: false,
  })),
  migrateLegacyVaultItemEncryptionAndMetadata: (...args: unknown[]) =>
    mockMigrateLegacyVaultItemEncryptionAndMetadata(...args),
}));

vi.mock('@/components/vault/VaultItemCard', () => ({
  VaultItemCard: ({ item }: { item: { decryptedData?: { title?: string } } }) => (
    <div>{item.decryptedData?.title || 'missing-title'}</div>
  ),
}));

vi.mock('@/components/vault/VaultQuarantinedItemCard', () => ({
  VaultQuarantinedItemCard: ({ itemId }: { itemId: string }) => (
    <div>Manipulierter Eintrag: {itemId}</div>
  ),
}));

const itemOk: SnapshotItem = {
  id: 'item-ok',
  vault_id: 'vault-1',
  title: 'Encrypted Item',
  website_url: null,
  icon_url: null,
  item_type: 'password',
  is_favorite: false,
  category_id: null,
  created_at: '2026-02-18T10:00:00.000Z',
  updated_at: '2026-02-18T10:00:00.000Z',
  encrypted_data: 'cipher-ok',
};

const itemBad: SnapshotItem = {
  id: 'item-bad',
  vault_id: 'vault-1',
  title: 'Encrypted Item',
  website_url: null,
  icon_url: null,
  item_type: 'password',
  is_favorite: false,
  category_id: null,
  created_at: '2026-02-18T10:00:00.000Z',
  updated_at: '2026-02-18T09:00:00.000Z',
  encrypted_data: 'cipher-bad',
};

const itemBadTotp: SnapshotItem = {
  ...itemBad,
  id: 'item-bad-totp',
  item_type: 'totp',
  encrypted_data: 'cipher-bad-totp',
};

describe.sequential('VaultItemList', () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    snapshotState.items = [itemOk, itemBad];
    snapshotState.online = false;
    snapshotState.source = 'remote';
    mockVaultContext.lastIntegrityResult = null;
    mockVaultContext.vaultDataVersion = 0;
    mockVaultContext.quarantineResolutionById = {};
    mockVaultContext.restoreQuarantinedItem.mockResolvedValue({ error: null });
    mockVaultContext.deleteQuarantinedItem.mockResolvedValue({ error: null });
    mockVaultContext.acceptMissingQuarantinedItem.mockResolvedValue({ error: null });
    mockEncryptItem.mockResolvedValue('encrypted');
    mockDecryptItemForLegacyMigration.mockRejectedValue(new Error('not legacy'));
    mockMigrateLegacyVaultItemEncryptionAndMetadata.mockImplementation(async (input: {
      item: SnapshotItem;
      decryptedData: unknown;
    }) => ({
      item: {
        ...input.item,
        encrypted_data: 'aad-bound-cipher',
        updated_at: '2026-02-18T11:00:00.000Z',
      },
      decryptedData: input.decryptedData,
      migrated: true,
    }));
    mockRefreshIntegrityBaseline.mockResolvedValue(undefined);
    mockVerifyIntegrity.mockResolvedValue(null);
    mockReportUnreadableItems.mockClear();
    mockDecryptItem.mockImplementation(async (cipher: string) => {
      if (cipher.startsWith('cipher-bad')) {
        throw new Error('OperationError');
      }

      return {
        title: 'Visible Item',
        itemType: 'password',
        isFavorite: false,
        categoryId: null,
      };
    });
  });

  it('renders a single tampered item inline in the all-items origin list', async () => {
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        {
          id: 'item-bad',
          reason: 'ciphertext_changed',
          updatedAt: '2026-02-18T09:00:00.000Z',
          itemType: 'password',
        },
      ],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Visible Item')).toBeInTheDocument();
      expect(screen.getByText('Manipulierter Eintrag: item-bad')).toBeInTheDocument();
    });

    expect(screen.queryByText('1 betroffene Einträge wurden zusammengefasst.')).not.toBeInTheDocument();
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([
      expect.objectContaining({
        id: 'item-bad',
        reason: 'decrypt_failed',
      }),
    ]);
  });

  it('groups two mixed-type tampered items only in the all-items quarantine summary', async () => {
    snapshotState.items = [itemOk, itemBad, itemBadTotp];
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        {
          id: 'item-bad',
          reason: 'ciphertext_changed',
          updatedAt: '2026-02-18T09:00:00.000Z',
          itemType: 'password',
        },
        {
          id: 'item-bad-totp',
          reason: 'ciphertext_changed',
          updatedAt: '2026-02-18T09:00:00.000Z',
          itemType: 'totp',
        },
      ],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Visible Item')).toBeInTheDocument();
      expect(screen.getByText('2 betroffene Einträge wurden zusammengefasst.')).toBeInTheDocument();
      expect(screen.getByText('Manipulierter Authenticator-Eintrag')).toBeInTheDocument();
    });

    expect(screen.queryByText('Manipulierter Eintrag: item-bad')).not.toBeInTheDocument();
    expect(screen.queryByText('Manipulierter Eintrag: item-bad-totp')).not.toBeInTheDocument();
  });

  it('keeps grouped quarantine entries out of origin filters', async () => {
    snapshotState.items = [itemOk, itemBad, itemBadTotp];
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        { id: 'item-bad', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
        { id: 'item-bad-totp', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
      ],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="passwords"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Visible Item')).toBeInTheDocument();
    });

    expect(screen.queryByText('2 betroffene Einträge wurden zusammengefasst.')).not.toBeInTheDocument();
    expect(screen.queryByText('Manipulierter Eintrag: item-bad')).not.toBeInTheDocument();
  });

  it('ignores a single grouped quarantine entry without hiding the others', async () => {
    snapshotState.items = [itemOk, itemBad, itemBadTotp];
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        { id: 'item-bad', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
        { id: 'item-bad-totp', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
      ],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('2 betroffene Einträge wurden zusammengefasst.');
    fireEvent.click(screen.getAllByRole('button', { name: 'Ignorieren' })[0]);

    expect(screen.queryByText('2 betroffene Einträge wurden zusammengefasst.')).not.toBeInTheDocument();
    expect(screen.queryByText('item-bad')).not.toBeInTheDocument();
    expect(screen.getByText('item-bad-totp')).toBeInTheDocument();
    expect(screen.getByText(/1 manipulierte/)).toBeInTheDocument();

    fireEvent.click(screen.getByText('Quarantäne anzeigen'));
    expect(screen.getByText(/Ignorierte Quarant/)).toBeInTheDocument();
    expect(screen.getByText('item-bad')).toBeInTheDocument();
  });

  it('ignores all currently visible grouped quarantine entries only through the explicit bulk action', async () => {
    snapshotState.items = [itemOk, itemBad, itemBadTotp];
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        { id: 'item-bad', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
        { id: 'item-bad-totp', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
      ],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('2 betroffene Einträge wurden zusammengefasst.');
    fireEvent.click(screen.getByRole('button', { name: 'Alle sichtbaren ignorieren' }));

    expect(screen.queryByText('2 betroffene Einträge wurden zusammengefasst.')).not.toBeInTheDocument();
    expect(screen.getByText(/2 manipulierte/)).toBeInTheDocument();

    fireEvent.click(screen.getByText('Quarantäne anzeigen'));
    expect(screen.getByText(/Ignorierte Quarant/)).toBeInTheDocument();
    expect(screen.getByText('item-bad')).toBeInTheDocument();
    expect(screen.getByText('item-bad-totp')).toBeInTheDocument();
  });

  it('revalidates remote integrity after rendering a cached snapshot while online', async () => {
    snapshotState.source = 'cache';
    snapshotState.online = true;
    snapshotState.items = [itemOk];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('Visible Item');

    await waitFor(() => {
      expect(mockVerifyIntegrity).toHaveBeenCalledWith();
    });
    expect(mockVerifyIntegrity).toHaveBeenCalledWith(expect.any(Object), { source: 'cache' });
  });

  it('refreshes the vault list from the cloud when the window regains focus online', async () => {
    snapshotState.source = 'remote';
    snapshotState.online = true;
    snapshotState.items = [itemOk];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('Visible Item');
    expect(loadVaultSnapshot).toHaveBeenCalledTimes(1);

    act(() => {
      window.dispatchEvent(new Event('focus'));
    });

    await waitFor(() => {
      expect(loadVaultSnapshot).toHaveBeenCalledTimes(2);
    });
  });

  it('keeps rendered entries visible while a cloud refresh runs in the background', async () => {
    snapshotState.source = 'remote';
    snapshotState.online = true;
    snapshotState.items = [itemOk];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('Visible Item');

    let resolveBackgroundLoad: (value: Awaited<ReturnType<typeof loadVaultSnapshot>>) => void = () => {};
    vi.mocked(loadVaultSnapshot).mockImplementationOnce(() => new Promise((resolve) => {
      resolveBackgroundLoad = resolve;
    }) as ReturnType<typeof loadVaultSnapshot>);

    act(() => {
      window.dispatchEvent(new Event('focus'));
    });

    expect(await screen.findByText('Synchronisiere mit Cloud...')).toBeInTheDocument();
    expect(screen.getByText('Visible Item')).toBeInTheDocument();
    expect(screen.queryByText('common.loading')).not.toBeInTheDocument();
    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();

    await act(async () => {
      resolveBackgroundLoad({
        source: 'remote',
        snapshot: {
          vaultId: 'vault-1',
          categories: [],
          items: [itemOk],
        },
      });
    });

    await screen.findByText('Zuletzt synchronisiert vor wenigen Sekunden');
  });

  it('migrates a healthy legacy no-AAD item instead of reporting quarantine', async () => {
    snapshotState.online = true;
    snapshotState.source = 'remote';
    snapshotState.items = [itemBad];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });
    mockDecryptItemForLegacyMigration.mockResolvedValue({
      data: {
        title: 'Legacy Visible Item',
        itemType: 'password',
        isFavorite: false,
        categoryId: null,
      },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: true,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('Legacy Visible Item');

    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        vaultId: 'vault-1',
        item: itemBad,
      }),
    );
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
    expect(mockRefreshIntegrityBaseline).toHaveBeenCalledWith(
      expect.objectContaining({
        itemIds: expect.any(Set),
      }),
    );
  });

  it('renders V2-native item envelopes without sending them through legacy migration', async () => {
    snapshotState.online = true;
    snapshotState.source = 'remote';
    snapshotState.items = [{
      ...itemOk,
      encrypted_data: 'sv-vault-v2:opaque-test-envelope',
    }];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });
    mockDecryptItem.mockResolvedValue({
      title: 'V2 Visible Item',
      itemType: 'password',
      isFavorite: false,
      categoryId: null,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await screen.findByText('V2 Visible Item');

    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).not.toHaveBeenCalled();
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
  });

  it('migrates legacy no-AAD items from runtime decrypt-failed quarantine', async () => {
    snapshotState.online = true;
    snapshotState.source = 'remote';
    snapshotState.items = [itemBad];
    const runtimeDecryptFailedItems = [
      {
        id: 'item-bad',
        reason: 'decrypt_failed' as const,
        updatedAt: '2026-02-18T09:00:00.000Z',
        itemType: 'password' as const,
      },
    ];
    mockVaultContext.lastIntegrityResult = {
      mode: 'quarantine',
      quarantinedItems: runtimeDecryptFailedItems,
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: runtimeDecryptFailedItems,
      isFirstCheck: false,
    });
    mockDecryptItemForLegacyMigration.mockResolvedValue({
      data: {
        title: 'Recovered Legacy Item',
        itemType: 'password',
        isFavorite: false,
        categoryId: null,
      },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: true,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    await waitFor(() => {
      expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).toHaveBeenCalled();
    });

    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        vaultId: 'vault-1',
        item: itemBad,
      }),
    );
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
    expect(mockRefreshIntegrityBaseline).toHaveBeenCalledWith(
      expect.objectContaining({
        itemIds: expect.any(Set),
      }),
    );
  });

  it('replays exactly one fetch when refresh changes during an in-flight load', async () => {
    let resolveFirstLoad: (value: unknown) => void = () => undefined;
    vi.mocked(loadVaultSnapshot)
      .mockImplementationOnce(() => new Promise((resolve) => {
        resolveFirstLoad = resolve;
      }) as ReturnType<typeof loadVaultSnapshot>)
      .mockImplementationOnce(async () => ({
        source: 'remote',
        snapshot: {
          vaultId: 'vault-1',
          categories: [],
          items: [itemOk],
        },
      }));

    const { rerender } = render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
        refreshKey={0}
      />,
    );

    await waitFor(() => {
      expect(loadVaultSnapshot).toHaveBeenCalledTimes(1);
    });

    rerender(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
        refreshKey={1}
      />,
    );

    expect(loadVaultSnapshot).toHaveBeenCalledTimes(1);

    resolveFirstLoad({
      source: 'remote',
      snapshot: {
        vaultId: 'vault-1',
        categories: [],
        items: [itemOk],
      },
    });

    await waitFor(() => {
      expect(loadVaultSnapshot).toHaveBeenCalledTimes(2);
    });
    expect(await screen.findByText('Visible Item')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('common.loading')).not.toBeInTheDocument();
      expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
      expect(screen.queryByText('Synchronisiere mit Cloud...')).not.toBeInTheDocument();
    });
  });

  it('does not poison decrypt-failed cache when legacy encryption migration persistence fails', async () => {
    snapshotState.online = true;
    snapshotState.source = 'remote';
    snapshotState.items = [itemBad];
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });
    mockDecryptItemForLegacyMigration.mockResolvedValue({
      data: {
        title: 'Readable Legacy Item',
        itemType: 'password',
        isFavorite: false,
        categoryId: null,
      },
      legacyEnvelopeUsed: true,
      legacyNoAadFallbackUsed: true,
    });
    mockMigrateLegacyVaultItemEncryptionAndMetadata.mockRejectedValue(
      new MockLegacyVaultMetadataMigrationPersistenceError('item-bad'),
    );

    const { rerender } = render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
        refreshKey={0}
      />,
    );

    await screen.findByText('Readable Legacy Item');
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);

    rerender(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
        refreshKey={1}
      />,
    );

    await waitFor(() => {
      expect(mockDecryptItemForLegacyMigration).toHaveBeenCalledTimes(2);
    });
    expect(mockReportUnreadableItems).toHaveBeenLastCalledWith([]);
  });

  it('confirms and restores all visible restorable quarantine entries one by one', async () => {
    snapshotState.items = [itemOk, itemBad, itemBadTotp];
    mockVaultContext.lastIntegrityResult = {
      mode: 'quarantine',
      quarantinedItems: [
        { id: 'item-bad', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
        { id: 'item-bad-totp', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
      ],
    };
    mockVaultContext.quarantineResolutionById = {
      'item-bad': {
        canRestore: true,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
      'item-bad-totp': {
        canRestore: true,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: mockVaultContext.lastIntegrityResult.quarantinedItems,
    });

    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={vi.fn()}
      />,
    );

    fireEvent.click(await screen.findByRole('button', {
      name: 'Alle wiederherstellbaren wiederherstellen',
    }));
    fireEvent.click(await screen.findByRole('button', {
      name: 'Wiederherstellen',
    }));

    await waitFor(() => {
      expect(mockVaultContext.restoreQuarantinedItem).toHaveBeenCalledWith('item-bad');
      expect(mockVaultContext.restoreQuarantinedItem).toHaveBeenCalledWith('item-bad-totp');
    });
    expect(await screen.findByText('2 Einträge wurden wiederhergestellt')).toBeInTheDocument();
  });
});
