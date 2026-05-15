// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Tests for VaultItemList Component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import { VaultItemList } from '../VaultItemList';
import { loadVaultSnapshot } from '@/services/offlineVaultService';

type SnapshotItem = {
  id: string;
  user_id: string;
  vault_id: string;
  title: string;
  website_url: string | null;
  icon_url: string | null;
  item_type: 'password' | 'note' | 'totp';
  is_favorite: boolean;
  category_id: string | null;
  sort_order: number;
  last_used_at: string;
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
  vaultMigrationStatus: null as null | 'notNeeded' | 'required' | 'preflightFailed' | 'ready' | 'running' | 'committed' | 'verified' | 'failed',
  opLogLocalVaultState: null as null | {
    recordsById: Map<string, unknown>;
    quarantinedRecordsById: Map<string, unknown>;
    conflictsByRecordId: Map<string, unknown>;
    trustedDevicesById: Map<string, unknown>;
    lastVerifiedVaultHead: string | null;
  },
  opLogUiView: null as null | {
    vaultSecurityMode: string;
    verifiedItems: Array<{ recordId: string; recordType: string; recordVersion: number }>;
    quarantinedItems: unknown[];
    conflictedItems: unknown[];
    deletedItemIds: string[];
    restoredItemIds: string[];
  },
  opLogUiRefresh: vi.fn(),
  opLogUpdateItem: vi.fn(),
  quarantineResolutionById: {} as Record<string, {
    canRestore: boolean;
    canDelete: boolean;
    hasTrustedLocalCopy: boolean;
    isBusy: boolean;
    lastError: string | null;
  }>,
  opLogRestoreRecord: vi.fn(),
  opLogDeleteUntrustedRecord: vi.fn(),
  lastIntegrityResult: null as
    | null
    | {
        mode?: 'healthy' | 'quarantine' | 'blocked' | 'revalidation_failed' | 'integrity_unknown';
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
      userId: 'user-1',
      vaultId: 'vault-1',
      categories: [],
      items: snapshotState.items,
      lastSyncedAt: '2026-02-18T10:00:00.000Z',
      updatedAt: '2026-02-18T10:00:00.000Z',
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
  user_id: 'user-1',
  vault_id: 'vault-1',
  title: 'Encrypted Item',
  website_url: null,
  icon_url: null,
  item_type: 'password',
  is_favorite: false,
  category_id: null,
  sort_order: 0,
  last_used_at: '2026-02-18T10:00:00.000Z',
  created_at: '2026-02-18T10:00:00.000Z',
  updated_at: '2026-02-18T10:00:00.000Z',
  encrypted_data: 'cipher-ok',
};

const itemBad: SnapshotItem = {
  id: 'item-bad',
  user_id: 'user-1',
  vault_id: 'vault-1',
  title: 'Encrypted Item',
  website_url: null,
  icon_url: null,
  item_type: 'password',
  is_favorite: false,
  category_id: null,
  sort_order: 0,
  last_used_at: '2026-02-18T09:00:00.000Z',
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

function renderList() {
  return render(
    <VaultItemList
      searchQuery=""
      filter="all"
      categoryId={null}
      viewMode="grid"
      onEditItem={vi.fn()}
    />,
  );
}

function makeVerifiedOpLogItem(recordId: string, plaintext: Record<string, unknown>) {
  return {
    record: {
      vaultId: 'vault-1',
      recordId,
      recordType: 'item',
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
    recordState: 'verified',
    plaintext: new TextEncoder().encode(JSON.stringify(plaintext)),
    lastOperation: {
      opId: 'op-1',
    },
  };
}

function makeVerifiedOpLogCategory(recordId: string, plaintext: Record<string, unknown>) {
  return {
    record: {
      vaultId: 'vault-1',
      recordId,
      recordType: 'category',
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
    recordState: 'verified',
    plaintext: new TextEncoder().encode(JSON.stringify(plaintext)),
    lastOperation: {
      opId: 'op-1',
    },
  };
}

function makeOpLogState(records: Array<ReturnType<typeof makeVerifiedOpLogItem> | ReturnType<typeof makeVerifiedOpLogCategory>>) {
  return {
    recordsById: new Map(records.map((record) => [record.record.recordId, record])),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map(),
    lastVerifiedVaultHead: 'head-1',
  };
}

describe.sequential('VaultItemList', () => {
  afterEach(() => {
    vi.useRealTimers();
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
    mockVaultContext.vaultMigrationStatus = null;
    mockVaultContext.opLogLocalVaultState = null;
    mockVaultContext.opLogUiView = null;
    mockVaultContext.opLogUiRefresh.mockResolvedValue(undefined);
    mockVaultContext.opLogUiRefresh.mockClear();
    mockVaultContext.opLogUpdateItem.mockResolvedValue({ error: null });
    mockVaultContext.opLogUpdateItem.mockClear();
    mockVaultContext.quarantineResolutionById = {};
    mockVaultContext.opLogRestoreRecord.mockResolvedValue({ error: null });
    mockVaultContext.opLogDeleteUntrustedRecord.mockResolvedValue({ error: null });
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
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });

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
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
  });

  it('opens the preview and clears the temporary glow for a focused vault health item', async () => {
    vi.useFakeTimers();
    const scrollIntoView = vi.fn();
    const originalRequestAnimationFrame = window.requestAnimationFrame;
    const originalScrollIntoView = HTMLElement.prototype.scrollIntoView;
    window.requestAnimationFrame = ((callback: FrameRequestCallback) => {
      callback(0);
      return 0;
    }) as typeof window.requestAnimationFrame;
    Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
      configurable: true,
      value: scrollIntoView,
    });

    try {
      const { container } = render(
        <VaultItemList
          searchQuery=""
          filter="all"
          categoryId={null}
          viewMode="grid"
          onEditItem={vi.fn()}
          focusItemId="item-ok"
        />,
      );

      await act(async () => {
        await Promise.resolve();
        await Promise.resolve();
      });

      const focusedElement = container.querySelector('[data-vault-item-id="item-ok"]');
      expect(focusedElement).not.toBeNull();
      expect(focusedElement?.className).toContain('ring-2');
      expect(scrollIntoView).toHaveBeenCalled();
      expect(screen.getByText('Eintrag bearbeiten')).toBeInTheDocument();

      act(() => {
        vi.advanceTimersByTime(10_000);
      });

      expect(focusedElement?.className).not.toContain('ring-2');
    } finally {
      window.requestAnimationFrame = originalRequestAnimationFrame;
      Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', {
        configurable: true,
        value: originalScrollIntoView,
      });
    }
  });

  it('does not decrypt when fresh integrity result is revalidation_failed even if previous context was healthy', async () => {
    mockVaultContext.lastIntegrityResult = {
      mode: 'healthy',
      quarantinedItems: [],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'revalidation_failed',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockVerifyIntegrity).toHaveBeenCalled();
    });
    expect(mockDecryptItem).not.toHaveBeenCalled();
    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).not.toHaveBeenCalled();
  });

  it('does not decrypt when fresh integrity result is integrity_unknown even if previous context was healthy', async () => {
    mockVaultContext.lastIntegrityResult = {
      mode: 'healthy',
      quarantinedItems: [],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'integrity_unknown',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockVerifyIntegrity).toHaveBeenCalled();
    });
    expect(mockDecryptItem).not.toHaveBeenCalled();
    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).not.toHaveBeenCalled();
  });

  it('does not run the legacy manifest verifier after OpLog migration is verified', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    mockVaultContext.opLogLocalVaultState = makeOpLogState([
      makeVerifiedOpLogItem('oplog-item-1', {
        title: 'Visible OpLog Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
      }),
    ]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [{ recordId: 'oplog-item-1', recordType: 'item', recordVersion: 1 }],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    await waitFor(() => {
      expect(screen.getByText('Visible OpLog Item')).toBeInTheDocument();
    });

    expect(loadVaultSnapshot).not.toHaveBeenCalled();
    expect(mockVerifyIntegrity).not.toHaveBeenCalled();
    expect(mockRefreshIntegrityBaseline).not.toHaveBeenCalled();
  });

  it('keeps the recent table filled after a row is used', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    const records = Array.from({ length: 9 }, (_, index) => makeVerifiedOpLogItem(`recent-item-${index + 1}`, {
      title: `Recent Item ${index + 1}`,
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: null,
      username: `user-${index + 1}`,
      password: `password-${index + 1}`,
    }));
    mockVaultContext.opLogLocalVaultState = makeOpLogState(records);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: records.map((record) => ({
        recordId: record.record.recordId,
        recordType: 'item',
        recordVersion: 1,
      })),
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    const onEditItem = vi.fn();
    render(
      <VaultItemList
        searchQuery=""
        filter="all"
        categoryId={null}
        viewMode="grid"
        onEditItem={onEditItem}
      />,
    );

    const recentSection = (await screen.findByText('Zuletzt verwendet')).closest('section');
    expect(recentSection).not.toBeNull();
    expect(within(recentSection!).getByText('Recent Item 8')).toBeInTheDocument();
    expect(within(recentSection!).queryByText('Recent Item 9')).not.toBeInTheDocument();

    fireEvent.click(within(recentSection!).getByText('Recent Item 3'));

    expect(onEditItem).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole('button', { name: /Eintrag bearbeiten/i }));
    expect(onEditItem).toHaveBeenCalledWith('recent-item-3');
    expect(within(recentSection!).getByText('Recent Item 3')).toBeInTheDocument();
    expect(within(recentSection!).getByText('Recent Item 8')).toBeInTheDocument();
    expect(within(recentSection!).queryByText('Recent Item 9')).not.toBeInTheDocument();
  });

  it('groups entries by category and submits a signed update when an item is dropped into a category', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    const category = makeVerifiedOpLogCategory('category-work', { name: 'Arbeit' });
    const categorizedItem = makeVerifiedOpLogItem('work-item', {
      title: 'Work Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: 'category-work',
      username: 'work-user',
      password: 'work-password',
    });
    const looseItem = makeVerifiedOpLogItem('loose-item', {
      title: 'Loose Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: null,
      username: 'loose-user',
      password: 'loose-password',
    });
    mockVaultContext.opLogLocalVaultState = makeOpLogState([category, categorizedItem, looseItem]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [
        { recordId: 'work-item', recordType: 'item', recordVersion: 1 },
        { recordId: 'loose-item', recordType: 'item', recordVersion: 1 },
      ],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    const categoryHeader = await screen.findByText('Arbeit');
    const dataTransfer = {
      types: ['application/x-singra-vault-item-id'],
      getData: vi.fn((type: string) => (type === 'application/x-singra-vault-item-id' ? 'loose-item' : '')),
      setData: vi.fn(),
      effectAllowed: '',
      dropEffect: '',
    };

    fireEvent.dragOver(categoryHeader, { dataTransfer });
    fireEvent.drop(categoryHeader, { dataTransfer });

    await waitFor(() => {
      expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
        'loose-item',
        expect.objectContaining({ categoryRecordId: 'category-work' }),
      );
    });
  });

  it('does not submit a signed update when an item is dropped on its current category', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    const category = makeVerifiedOpLogCategory('category-work', { name: 'Arbeit' });
    const categorizedItem = makeVerifiedOpLogItem('work-item', {
      title: 'Work Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: 'category-work',
      username: 'work-user',
      password: 'work-password',
    });
    const looseItem = makeVerifiedOpLogItem('loose-item', {
      title: 'Loose Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: null,
      username: 'loose-user',
      password: 'loose-password',
    });
    mockVaultContext.opLogLocalVaultState = makeOpLogState([category, categorizedItem, looseItem]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [
        { recordId: 'work-item', recordType: 'item', recordVersion: 1 },
        { recordId: 'loose-item', recordType: 'item', recordVersion: 1 },
      ],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    const categoryHeader = await screen.findByText('Arbeit');
    const dataTransfer = {
      types: ['application/x-singra-vault-item-id'],
      getData: vi.fn((type: string) => (type === 'application/x-singra-vault-item-id' ? 'work-item' : '')),
      setData: vi.fn(),
      effectAllowed: '',
      dropEffect: '',
    };

    fireEvent.dragOver(categoryHeader, { dataTransfer });
    fireEvent.drop(categoryHeader, { dataTransfer });
    await act(async () => {
      await Promise.resolve();
    });

    expect(mockVaultContext.opLogUpdateItem).not.toHaveBeenCalled();
  });

  it('submits a signed category move from the touch drag handle after a long press', async () => {
    const originalSetPointerCapture = HTMLElement.prototype.setPointerCapture;
    const originalReleasePointerCapture = HTMLElement.prototype.releasePointerCapture;
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(HTMLElement.prototype, 'setPointerCapture', {
      configurable: true,
      value: vi.fn(),
    });
    Object.defineProperty(HTMLElement.prototype, 'releasePointerCapture', {
      configurable: true,
      value: vi.fn(),
    });

    try {
      mockVaultContext.vaultMigrationStatus = 'verified';
      const category = makeVerifiedOpLogCategory('category-work', { name: 'Arbeit' });
      const categorizedItem = makeVerifiedOpLogItem('work-item', {
        title: 'Work Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: 'category-work',
        username: 'work-user',
        password: 'work-password',
      });
      const looseItem = makeVerifiedOpLogItem('loose-item', {
        title: 'Loose Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'loose-user',
        password: 'loose-password',
      });
      mockVaultContext.opLogLocalVaultState = makeOpLogState([category, categorizedItem, looseItem]);
      mockVaultContext.opLogUiView = {
        vaultSecurityMode: 'normal',
        verifiedItems: [
          { recordId: 'work-item', recordType: 'item', recordVersion: 1 },
          { recordId: 'loose-item', recordType: 'item', recordVersion: 1 },
        ],
        quarantinedItems: [],
        conflictedItems: [],
        deletedItemIds: [],
        restoredItemIds: [],
      };

      renderList();

      const categoryLabel = await screen.findByText('Arbeit');
      const categoryDropTarget = categoryLabel.closest('[data-vault-category-drop-id]');
      expect(categoryDropTarget).not.toBeNull();
      Object.defineProperty(document, 'elementFromPoint', {
        configurable: true,
        value: vi.fn(() => categoryDropTarget),
      });

      const handles = await screen.findAllByLabelText('Eintrag verschieben');
      const looseHandle = handles.find((handle) => (
        handle.closest('[draggable="true"]')?.textContent?.includes('Loose Item')
      ));
      expect(looseHandle).toBeDefined();

      vi.useFakeTimers();
      fireEvent.pointerDown(looseHandle as HTMLElement, {
        pointerId: 1,
        pointerType: 'touch',
        button: 0,
        clientX: 20,
        clientY: 20,
      });
      act(() => {
        vi.advanceTimersByTime(300);
      });
      fireEvent.pointerUp(looseHandle as HTMLElement, {
        pointerId: 1,
        pointerType: 'touch',
        button: 0,
        clientX: 20,
        clientY: 20,
      });

      await act(async () => {
        await Promise.resolve();
      });

      expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
        'loose-item',
        expect.objectContaining({ categoryRecordId: 'category-work' }),
      );
    } finally {
      if (originalSetPointerCapture) {
        Object.defineProperty(HTMLElement.prototype, 'setPointerCapture', {
          configurable: true,
          value: originalSetPointerCapture,
        });
      } else {
        delete (HTMLElement.prototype as Partial<HTMLElement>).setPointerCapture;
      }
      if (originalReleasePointerCapture) {
        Object.defineProperty(HTMLElement.prototype, 'releasePointerCapture', {
          configurable: true,
          value: originalReleasePointerCapture,
        });
      } else {
        delete (HTMLElement.prototype as Partial<HTMLElement>).releasePointerCapture;
      }
      Object.defineProperty(document, 'elementFromPoint', {
        configurable: true,
        value: originalElementFromPoint,
      });
      vi.useRealTimers();
    }
  });

  it('submits a signed category move from the pointer drag handle without native HTML drag', async () => {
    const originalSetPointerCapture = HTMLElement.prototype.setPointerCapture;
    const originalReleasePointerCapture = HTMLElement.prototype.releasePointerCapture;
    const originalElementFromPoint = document.elementFromPoint;
    Object.defineProperty(HTMLElement.prototype, 'setPointerCapture', {
      configurable: true,
      value: vi.fn(),
    });
    Object.defineProperty(HTMLElement.prototype, 'releasePointerCapture', {
      configurable: true,
      value: vi.fn(),
    });

    try {
      mockVaultContext.vaultMigrationStatus = 'verified';
      const category = makeVerifiedOpLogCategory('category-work', { name: 'Arbeit' });
      const categorizedItem = makeVerifiedOpLogItem('work-item', {
        title: 'Work Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: 'category-work',
        username: 'work-user',
        password: 'work-password',
      });
      const looseItem = makeVerifiedOpLogItem('loose-item', {
        title: 'Loose Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'loose-user',
        password: 'loose-password',
      });
      mockVaultContext.opLogLocalVaultState = makeOpLogState([category, categorizedItem, looseItem]);
      mockVaultContext.opLogUiView = {
        vaultSecurityMode: 'normal',
        verifiedItems: [
          { recordId: 'work-item', recordType: 'item', recordVersion: 1 },
          { recordId: 'loose-item', recordType: 'item', recordVersion: 1 },
        ],
        quarantinedItems: [],
        conflictedItems: [],
        deletedItemIds: [],
        restoredItemIds: [],
      };

      renderList();

      const categoryLabel = await screen.findByText('Arbeit');
      const categoryDropTarget = categoryLabel.closest('[data-vault-category-drop-id]');
      expect(categoryDropTarget).not.toBeNull();
      Object.defineProperty(document, 'elementFromPoint', {
        configurable: true,
        value: vi.fn(() => categoryDropTarget),
      });

      const handles = await screen.findAllByLabelText('Eintrag verschieben');
      const looseHandle = handles.find((handle) => (
        handle.closest('[draggable="true"]')?.textContent?.includes('Loose Item')
      ));
      expect(looseHandle).toBeDefined();

      fireEvent.pointerDown(looseHandle as HTMLElement, {
        pointerId: 2,
        pointerType: 'mouse',
        button: 0,
        clientX: 20,
        clientY: 20,
      });
      fireEvent.pointerUp(looseHandle as HTMLElement, {
        pointerId: 2,
        pointerType: 'mouse',
        button: 0,
        clientX: 20,
        clientY: 20,
      });

      await waitFor(() => {
        expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
          'loose-item',
          expect.objectContaining({ categoryRecordId: 'category-work' }),
        );
      });
    } finally {
      if (originalSetPointerCapture) {
        Object.defineProperty(HTMLElement.prototype, 'setPointerCapture', {
          configurable: true,
          value: originalSetPointerCapture,
        });
      } else {
        delete (HTMLElement.prototype as Partial<HTMLElement>).setPointerCapture;
      }
      if (originalReleasePointerCapture) {
        Object.defineProperty(HTMLElement.prototype, 'releasePointerCapture', {
          configurable: true,
          value: originalReleasePointerCapture,
        });
      } else {
        delete (HTMLElement.prototype as Partial<HTMLElement>).releasePointerCapture;
      }
      Object.defineProperty(document, 'elementFromPoint', {
        configurable: true,
        value: originalElementFromPoint,
      });
    }
  });

  it('submits a signed update when a table favorite star is toggled', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    const records = [
      makeVerifiedOpLogItem('favorite-item', {
        title: 'Favorite Candidate',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'fav-user',
        password: 'fav-password',
      }),
      makeVerifiedOpLogItem('other-item', {
        title: 'Other Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'other-user',
        password: 'other-password',
      }),
    ];
    mockVaultContext.opLogLocalVaultState = makeOpLogState(records);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: records.map((record) => ({
        recordId: record.record.recordId,
        recordType: 'item',
        recordVersion: 1,
      })),
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    const favoriteTitle = (await screen.findAllByText('Favorite Candidate'))[0];
    const favoriteRow = favoriteTitle.closest('[draggable="true"]');

    expect(favoriteRow).not.toBeNull();

    const favoriteButton = within(favoriteRow as HTMLElement).getByLabelText('Als Favorit markieren');
    fireEvent.click(favoriteButton);

    await waitFor(() => {
      expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
        'favorite-item',
        expect.objectContaining({ isFavorite: true }),
      );
    });
  });

  it('rate-limits rapid favorite toggles so OpLog writes can settle', async () => {
    mockVaultContext.vaultMigrationStatus = 'verified';
    const records = [
      makeVerifiedOpLogItem('favorite-item', {
        title: 'Favorite Candidate',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'fav-user',
        password: 'fav-password',
      }),
      makeVerifiedOpLogItem('other-item', {
        title: 'Other Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
        username: 'other-user',
        password: 'other-password',
      }),
    ];
    mockVaultContext.opLogLocalVaultState = makeOpLogState(records);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: records.map((record) => ({
        recordId: record.record.recordId,
        recordType: 'item',
        recordVersion: 1,
      })),
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    const favoriteRow = (await screen.findAllByText('Favorite Candidate'))[0].closest('[draggable="true"]');
    const otherRow = (await screen.findAllByText('Other Item'))[0].closest('[draggable="true"]');
    expect(favoriteRow).not.toBeNull();
    expect(otherRow).not.toBeNull();

    fireEvent.click(within(favoriteRow as HTMLElement).getByLabelText('Als Favorit markieren'));
    fireEvent.click(within(otherRow as HTMLElement).getByLabelText('Als Favorit markieren'));

    await waitFor(() => {
      expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledTimes(1);
    });
    expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
      'favorite-item',
      expect.objectContaining({ isFavorite: true }),
    );
  });

  it('keeps an empty verified OpLog vault on the empty state during background refresh', async () => {
    snapshotState.online = true;
    mockVaultContext.vaultMigrationStatus = 'verified';
    mockVaultContext.opLogLocalVaultState = makeOpLogState([]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    await screen.findByText('vault.empty.title');
    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();

    act(() => {
      window.dispatchEvent(new Event('focus'));
    });

    expect(await screen.findByText('vault.empty.title')).toBeInTheDocument();
    await waitFor(() => {
      expect(mockVaultContext.opLogUiRefresh).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
    expect(loadVaultSnapshot).not.toHaveBeenCalled();
    expect(mockVerifyIntegrity).not.toHaveBeenCalled();
  });

  it('does not show the decrypting label for an empty verified OpLog vault while the first view settles', async () => {
    snapshotState.online = true;
    mockVaultContext.vaultMigrationStatus = 'verified';
    mockVaultContext.opLogLocalVaultState = makeOpLogState([]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
    await screen.findByText('vault.empty.title');
    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
    expect(loadVaultSnapshot).not.toHaveBeenCalled();
    expect(mockVerifyIntegrity).not.toHaveBeenCalled();
  });

  it('does not show the decrypting label for an empty legacy snapshot while the first view settles', async () => {
    snapshotState.items = [];
    mockVaultContext.vaultMigrationStatus = null;

    let resolveInitialLoad: (value: Awaited<ReturnType<typeof loadVaultSnapshot>>) => void = () => {};
    vi.mocked(loadVaultSnapshot).mockImplementationOnce(() => new Promise((resolve) => {
      resolveInitialLoad = resolve;
    }) as ReturnType<typeof loadVaultSnapshot>);

    renderList();

    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
    expect(screen.getByText('common.loading')).toBeInTheDocument();

    await act(async () => {
      resolveInitialLoad({
        source: 'remote',
        snapshot: {
          userId: 'user-1',
          vaultId: 'vault-1',
          categories: [],
          items: [],
          lastSyncedAt: '2026-02-18T10:00:00.000Z',
          updatedAt: '2026-02-18T10:00:00.000Z',
        },
      });
    });

    expect(await screen.findByText('vault.empty.title')).toBeInTheDocument();
    expect(screen.queryByText('vault.items.decrypting')).not.toBeInTheDocument();
    expect(mockDecryptItem).not.toHaveBeenCalled();
  });

  it('refreshes the verified OpLog state on cloud sync ticks and clears the syncing indicator', async () => {
    snapshotState.online = true;
    mockVaultContext.vaultMigrationStatus = 'verified';
    mockVaultContext.opLogLocalVaultState = makeOpLogState([
      makeVerifiedOpLogItem('oplog-item-1', {
        title: 'Visible OpLog Item',
        itemType: 'password',
        isFavorite: false,
        categoryRecordId: null,
      }),
    ]);
    mockVaultContext.opLogUiView = {
      vaultSecurityMode: 'normal',
      verifiedItems: [{ recordId: 'oplog-item-1', recordType: 'item', recordVersion: 1 }],
      quarantinedItems: [],
      conflictedItems: [],
      deletedItemIds: [],
      restoredItemIds: [],
    };

    renderList();

    await screen.findByText('Visible OpLog Item');

    let resolveRefresh: () => void = () => {};
    mockVaultContext.opLogUiRefresh.mockImplementationOnce(() => new Promise<void>((resolve) => {
      resolveRefresh = resolve;
    }));

    act(() => {
      window.dispatchEvent(new Event('focus'));
    });

    expect(await screen.findByText('Synchronisiere mit Cloud...')).toBeInTheDocument();
    await waitFor(() => {
      expect(mockVaultContext.opLogUiRefresh).toHaveBeenCalledTimes(1);
    });
    await act(async () => {
      resolveRefresh();
    });
    await waitFor(() => {
      expect(screen.queryByText('Synchronisiere mit Cloud...')).not.toBeInTheDocument();
    });
    expect(loadVaultSnapshot).not.toHaveBeenCalled();
    expect(mockVerifyIntegrity).not.toHaveBeenCalled();
  });

  it('does not decrypt an item from the freshly returned quarantine result', async () => {
    mockVaultContext.lastIntegrityResult = {
      mode: 'healthy',
      quarantinedItems: [],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: [{ id: 'item-ok', reason: 'ciphertext_changed', updatedAt: null }],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockVerifyIntegrity).toHaveBeenCalled();
    });
    expect(mockDecryptItem).not.toHaveBeenCalledWith('cipher-ok', 'item-ok');
  });

  it('decrypts only non-quarantined items from the freshly returned quarantine result', async () => {
    mockVaultContext.lastIntegrityResult = {
      mode: 'healthy',
      quarantinedItems: [],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'quarantine',
      quarantinedItems: [{ id: 'item-bad', reason: 'ciphertext_changed', updatedAt: null }],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockDecryptItem).toHaveBeenCalledWith('cipher-ok', 'item-ok');
    });
    expect(mockDecryptItem).not.toHaveBeenCalledWith('cipher-bad', 'item-bad');
  });

  it('continues to decrypt normally when fresh integrity result is healthy', async () => {
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'healthy',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockDecryptItem).toHaveBeenCalledWith('cipher-ok', 'item-ok');
    });
  });

  it('fails closed for unknown fresh integrity modes', async () => {
    mockVaultContext.lastIntegrityResult = {
      mode: 'healthy',
      quarantinedItems: [],
    };
    mockVerifyIntegrity.mockResolvedValue({
      mode: 'future_mode',
      quarantinedItems: [],
      isFirstCheck: false,
    });

    renderList();

    await waitFor(() => {
      expect(mockVerifyIntegrity).toHaveBeenCalled();
    });
    expect(mockDecryptItem).not.toHaveBeenCalled();
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
          userId: 'user-1',
          vaultId: 'vault-1',
          categories: [],
          items: [itemOk],
          lastSyncedAt: '2026-02-18T10:00:00.000Z',
          updatedAt: '2026-02-18T10:00:00.000Z',
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
        item: expect.objectContaining({ id: itemBad.id }),
      }),
    );
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
    expect(mockRefreshIntegrityBaseline).toHaveBeenCalledWith();
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

  it('does not migrate items from runtime decrypt-failed quarantine', async () => {
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
      expect(mockVerifyIntegrity).toHaveBeenCalled();
    });
    expect(mockDecryptItem).not.toHaveBeenCalledWith('cipher-bad', 'item-bad');
    expect(mockMigrateLegacyVaultItemEncryptionAndMetadata).not.toHaveBeenCalled();
    expect(mockReportUnreadableItems).toHaveBeenCalledWith([]);
    expect(mockRefreshIntegrityBaseline).not.toHaveBeenCalled();
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
          userId: 'user-1',
          vaultId: 'vault-1',
          categories: [],
          items: [itemOk],
          lastSyncedAt: '2026-02-18T10:00:00.000Z',
          updatedAt: '2026-02-18T10:00:00.000Z',
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
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
      'item-bad-totp': {
        canRestore: true,
        canDelete: true,
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
      expect(mockVaultContext.opLogRestoreRecord).toHaveBeenCalledWith('item-bad');
      expect(mockVaultContext.opLogRestoreRecord).toHaveBeenCalledWith('item-bad-totp');
    });
    expect(await screen.findByText('2 Einträge wurden wiederhergestellt')).toBeInTheDocument();
  });
});
