// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Tests for VaultItemList Component
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

import { VaultItemList } from '../VaultItemList';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: string | { defaultValue?: string }) =>
      typeof options === 'string' ? options : options?.defaultValue || key,
  }),
}));

const mockDecryptItem = vi.fn();
const mockEncryptItem = vi.fn();
const mockVerifyIntegrity = vi.fn();
const mockRefreshIntegrityBaseline = vi.fn();

const mockVaultContext = {
  decryptItem: (...args: unknown[]) => mockDecryptItem(...args),
  encryptItem: (...args: unknown[]) => mockEncryptItem(...args),
  verifyIntegrity: (...args: unknown[]) => mockVerifyIntegrity(...args),
  refreshIntegrityBaseline: (...args: unknown[]) => mockRefreshIntegrityBaseline(...args),
  isDuressMode: false,
  lastIntegrityResult: null as
    | null
    | {
        quarantinedItems: Array<{
          id: string;
          reason: 'ciphertext_changed' | 'missing_on_server' | 'unknown_on_server';
          updatedAt: string | null;
        }>;
      },
};

vi.mock('@/contexts/VaultContext', () => ({
  useVault: () => mockVaultContext,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user-1' },
  }),
}));

vi.mock('@/services/offlineVaultService', () => ({
  loadVaultSnapshot: vi.fn().mockResolvedValue({
    source: 'offline',
    snapshot: {
      vaultId: 'vault-1',
      categories: [],
      items: [
        {
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
        },
        {
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
        },
      ],
    },
  }),
  isAppOnline: vi.fn().mockReturnValue(false),
  upsertOfflineItemRow: vi.fn(),
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

describe('VaultItemList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.lastIntegrityResult = null;
    mockEncryptItem.mockResolvedValue('encrypted');
    mockRefreshIntegrityBaseline.mockResolvedValue(undefined);
    mockVerifyIntegrity.mockResolvedValue(null);
    mockDecryptItem.mockImplementation(async (cipher: string) => {
      if (cipher === 'cipher-bad') {
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

  it('renders an inline quarantine placeholder for tampered items', async () => {
    mockVaultContext.lastIntegrityResult = {
      quarantinedItems: [
        {
          id: 'item-bad',
          reason: 'ciphertext_changed',
          updatedAt: '2026-02-18T09:00:00.000Z',
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

    expect(screen.queryByText('missing-title')).not.toBeInTheDocument();
    expect(mockVerifyIntegrity).toHaveBeenCalled();
  });
});
