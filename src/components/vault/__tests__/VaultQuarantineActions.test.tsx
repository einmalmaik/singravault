import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { VaultQuarantineActions } from '../VaultQuarantineActions';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, options?: string | { defaultValue?: string; [key: string]: unknown }) => {
      if (typeof options === 'string') {
        return options;
      }

      const fixedTranslations: Record<string, string> = {
        'common.success': 'Erfolgreich',
        'common.error': 'Fehler',
        'common.cancel': 'Abbrechen',
      };

      return options?.defaultValue || fixedTranslations[key] || key;
    },
  }),
}));

const mockRestoreQuarantinedItem = vi.fn();
const mockDeleteQuarantinedItem = vi.fn();
const mockAcceptMissingQuarantinedItem = vi.fn();
const mockToast = vi.fn();

const mockVaultContext = {
  restoreQuarantinedItem: (...args: unknown[]) => mockRestoreQuarantinedItem(...args),
  deleteQuarantinedItem: (...args: unknown[]) => mockDeleteQuarantinedItem(...args),
  acceptMissingQuarantinedItem: (...args: unknown[]) => mockAcceptMissingQuarantinedItem(...args),
  quarantineResolutionById: {} as Record<string, {
    reason: 'ciphertext_changed' | 'missing_on_server' | 'unknown_on_server';
    canRestore: boolean;
    canDelete: boolean;
    canAcceptMissing: boolean;
    hasTrustedLocalCopy: boolean;
    isBusy: boolean;
    lastError: string | null;
  }>,
};

vi.mock('@/contexts/VaultContext', () => ({
  useVault: () => mockVaultContext,
}));

vi.mock('@/hooks/use-toast', () => ({
  useToast: () => ({
    toast: (...args: unknown[]) => mockToast(...args),
  }),
}));

describe('VaultQuarantineActions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockVaultContext.quarantineResolutionById = {};
    mockRestoreQuarantinedItem.mockResolvedValue({ error: null });
    mockDeleteQuarantinedItem.mockResolvedValue({ error: null });
    mockAcceptMissingQuarantinedItem.mockResolvedValue({ error: null });
  });

  it('shows restore and delete for ciphertext drift with a trusted local copy', () => {
    mockVaultContext.quarantineResolutionById = {
      'item-1': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <VaultQuarantineActions
        item={{ id: 'item-1', reason: 'ciphertext_changed', updatedAt: null }}
      />,
    );

    expect(screen.getByRole('button', { name: 'Wiederherstellen' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Endgültig löschen' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Löschung akzeptieren' })).not.toBeInTheDocument();
    expect(screen.queryByText(/keine vertrauenswürdige lokale Kopie/i)).not.toBeInTheDocument();
  });

  it('shows accept-missing and missing trusted-copy hint for missing entries', () => {
    mockVaultContext.quarantineResolutionById = {
      'item-2': {
        reason: 'missing_on_server',
        canRestore: false,
        canDelete: false,
        canAcceptMissing: true,
        hasTrustedLocalCopy: false,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <VaultQuarantineActions
        item={{ id: 'item-2', reason: 'missing_on_server', updatedAt: null }}
      />,
    );

    expect(screen.getByRole('button', { name: 'Löschung akzeptieren' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wiederherstellen' })).not.toBeInTheDocument();
    expect(screen.getByText(/keine vertrauenswürdige lokale Kopie/i)).toBeInTheDocument();
  });

  it('calls restore directly for restorable entries', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-restore': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <VaultQuarantineActions
        item={{ id: 'item-restore', reason: 'ciphertext_changed', updatedAt: null }}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Wiederherstellen' }));

    await waitFor(() => {
      expect(mockRestoreQuarantinedItem).toHaveBeenCalledWith('item-restore');
    });
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Erfolgreich',
      description: 'Die letzte vertrauenswürdige lokale Version wurde wiederhergestellt.',
    }));
  });

  it('restores only the selected quarantined entry and leaves non-restorable entries untouched', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-restorable': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
      'item-not-restorable': {
        reason: 'ciphertext_changed',
        canRestore: false,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: false,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <>
        <VaultQuarantineActions
          item={{ id: 'item-restorable', reason: 'ciphertext_changed', updatedAt: null }}
        />
        <VaultQuarantineActions
          item={{ id: 'item-not-restorable', reason: 'ciphertext_changed', updatedAt: null }}
        />
      </>,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Wiederherstellen' }));

    await waitFor(() => {
      expect(mockRestoreQuarantinedItem).toHaveBeenCalledWith('item-restorable');
    });
    expect(mockRestoreQuarantinedItem).toHaveBeenCalledTimes(1);
    expect(mockRestoreQuarantinedItem).not.toHaveBeenCalledWith('item-not-restorable');
  });

  it('confirms accepting a missing entry before updating the baseline', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-missing': {
        reason: 'missing_on_server',
        canRestore: false,
        canDelete: false,
        canAcceptMissing: true,
        hasTrustedLocalCopy: false,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <VaultQuarantineActions
        item={{ id: 'item-missing', reason: 'missing_on_server', updatedAt: null }}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Löschung akzeptieren' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText('Löschung akzeptieren?')).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Löschung akzeptieren' }));

    await waitFor(() => {
      expect(mockAcceptMissingQuarantinedItem).toHaveBeenCalledWith('item-missing');
    });
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Erfolgreich',
      description: 'Die Löschung wurde akzeptiert und die lokale Vertrauensbasis aktualisiert.',
    }));
  });

  it('confirms deletion for unknown server items and calls the delete action', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-3': {
        reason: 'unknown_on_server',
        canRestore: false,
        canDelete: true,
        canAcceptMissing: false,
        hasTrustedLocalCopy: false,
        isBusy: false,
        lastError: null,
      },
    };

    render(
      <VaultQuarantineActions
        item={{ id: 'item-3', reason: 'unknown_on_server', updatedAt: null }}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Endgültig löschen' }));
    expect(screen.getByText('Eintrag endgültig löschen?')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Endgültig löschen' }));

    await waitFor(() => {
      expect(mockDeleteQuarantinedItem).toHaveBeenCalledWith('item-3');
    });
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Erfolgreich',
      description: 'Der Quarantäne-Eintrag wurde entfernt.',
    }));
  });
});
