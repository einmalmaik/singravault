import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import { VaultSidebar } from '../VaultSidebar';
import { TooltipProvider } from '@/components/ui/tooltip';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: string | { defaultValue?: string }) => (
      typeof options === 'string' ? options : options?.defaultValue || key
    ),
  }),
}));

vi.mock('@/hooks/useFeatureGate', () => ({
  useFeatureGate: () => ({ allowed: true }),
}));

vi.mock('@/extensions/registry', () => ({
  isPremiumActive: () => true,
}));

vi.mock('@/services/offlineVaultService', () => ({
  loadVaultSnapshot: vi.fn(),
}));

vi.mock('@/services/legacyVaultMetadataMigrationService', () => ({
  migrateLegacyVaultItemMetadata: vi.fn(),
}));

const mockVaultContext = {
  lock: vi.fn(),
  decryptData: vi.fn(),
  decryptItem: vi.fn(),
  isDuressMode: false,
  lastIntegrityResult: null,
  verifyIntegrity: vi.fn(),
  vaultDataVersion: 0,
  vaultMigrationStatus: 'verified' as const,
  opLogLocalVaultState: null as null | {
    recordsById: Map<string, unknown>;
  },
  opLogUpdateItem: vi.fn(),
};

vi.mock('@/contexts/VaultContext', () => ({
  useVault: () => mockVaultContext,
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'user-1', email: 'maik@example.test' } }),
}));

function makeVerifiedRecord(recordId: string, recordType: 'item' | 'category', plaintext: Record<string, unknown>) {
  return {
    record: {
      vaultId: 'vault-1',
      recordId,
      recordType,
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

describe('VaultSidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.opLogUpdateItem.mockResolvedValue({ error: null });
    const category = makeVerifiedRecord('category-work', 'category', { name: 'Arbeit' });
    const item = makeVerifiedRecord('loose-item', 'item', {
      title: 'Loose Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: null,
      username: 'loose-user',
      password: 'loose-password',
    });
    const categorizedItem = makeVerifiedRecord('categorized-item', 'item', {
      title: 'Categorized Item',
      itemType: 'password',
      isFavorite: false,
      categoryRecordId: 'category-work',
      username: 'categorized-user',
      password: 'categorized-password',
    });
    mockVaultContext.opLogLocalVaultState = {
      recordsById: new Map([
        ['category-work', category],
        ['loose-item', item],
        ['categorized-item', categorizedItem],
      ]),
    };
  });

  afterEach(() => {
    cleanup();
  });

  it('moves a dropped item without selecting the target category', async () => {
    const onSelectCategory = vi.fn();
    const onActionComplete = vi.fn();

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <TooltipProvider>
          <VaultSidebar
            selectedCategory={null}
            onSelectCategory={onSelectCategory}
            onActionComplete={onActionComplete}
          />
        </TooltipProvider>
      </MemoryRouter>,
    );

    const categoryLabel = await screen.findByText('Arbeit');
    const categoryDropTarget = categoryLabel.closest('[data-vault-category-drop-id]');
    expect(categoryDropTarget).not.toBeNull();

    const dataTransfer = {
      getData: vi.fn((type: string) => (
        type === 'application/x-singra-vault-item-id' ? 'loose-item' : ''
      )),
      setData: vi.fn(),
      effectAllowed: '',
      dropEffect: '',
    };

    fireEvent.drop(categoryDropTarget as HTMLElement, { dataTransfer });
    fireEvent.click(categoryLabel);

    await waitFor(() => {
      expect(mockVaultContext.opLogUpdateItem).toHaveBeenCalledWith(
        'loose-item',
        expect.objectContaining({ categoryRecordId: 'category-work' }),
      );
    });
    expect(onSelectCategory).not.toHaveBeenCalled();
    expect(onActionComplete).toHaveBeenCalled();
  });

  it('does not submit a signed update when a sidebar drop keeps the same category', async () => {
    const onSelectCategory = vi.fn();
    const onActionComplete = vi.fn();

    render(
      <MemoryRouter initialEntries={['/vault']}>
        <TooltipProvider>
          <VaultSidebar
            selectedCategory={null}
            onSelectCategory={onSelectCategory}
            onActionComplete={onActionComplete}
          />
        </TooltipProvider>
      </MemoryRouter>,
    );

    const categoryLabel = await screen.findByText('Arbeit');
    const categoryDropTarget = categoryLabel.closest('[data-vault-category-drop-id]');
    expect(categoryDropTarget).not.toBeNull();

    const dataTransfer = {
      getData: vi.fn((type: string) => (
        type === 'application/x-singra-vault-item-id' ? 'categorized-item' : ''
      )),
      setData: vi.fn(),
      effectAllowed: '',
      dropEffect: '',
    };

    fireEvent.drop(categoryDropTarget as HTMLElement, { dataTransfer });
    fireEvent.click(categoryLabel);

    await new Promise((resolve) => {
      setTimeout(resolve, 0);
    });

    expect(mockVaultContext.opLogUpdateItem).not.toHaveBeenCalled();
    expect(onSelectCategory).not.toHaveBeenCalled();
    expect(onActionComplete).not.toHaveBeenCalled();
  });
});
