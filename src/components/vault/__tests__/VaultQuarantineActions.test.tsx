import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
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
        'vault.integrity.restoreAction': 'Wiederherstellen',
        'vault.integrity.deleteEntry': 'Endgueltig loeschen',
        'vault.integrity.noTrustedLocalCopy': 'Auf diesem Geraet ist keine verifizierte lokale Kopie verfuegbar.',
        'vault.integrity.restoreSuccess': 'Die letzte verifizierte Version wurde ueber das Operation Log wiederhergestellt.',
        'vault.integrity.deleteSuccess': 'Der Quarantaene-Eintrag wurde ueber eine signierte Tombstone-Operation entfernt.',
        'vault.integrity.confirmDeleteTitle': 'Eintrag endgueltig loeschen?',
      };

      return fixedTranslations[key] || options?.defaultValue || key;
    },
  }),
}));

const mockOpLogRestoreRecord = vi.fn();
const mockOpLogDeleteUntrustedRecord = vi.fn();
const mockToast = vi.fn();

const mockVaultContext = {
  opLogRestoreRecord: (...args: unknown[]) => mockOpLogRestoreRecord(...args),
  opLogDeleteUntrustedRecord: (...args: unknown[]) => mockOpLogDeleteUntrustedRecord(...args),
  quarantineResolutionById: {} as Record<string, {
    reason: 'ciphertext_changed' | 'missing_on_server' | 'unknown_on_server';
    canRestore: boolean;
    canDelete: boolean;
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
    mockOpLogRestoreRecord.mockResolvedValue({ error: null });
    mockOpLogDeleteUntrustedRecord.mockResolvedValue({ error: null });
  });

  it('shows restore and delete for ciphertext drift with a trusted local copy', () => {
    mockVaultContext.quarantineResolutionById = {
      'item-1': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
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
    expect(screen.getByRole('button', { name: 'Endgueltig loeschen' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Loeschung akzeptieren' })).not.toBeInTheDocument();
    expect(screen.queryByText(/keine verifizierte lokale Kopie/i)).not.toBeInTheDocument();
  });

  it('shows the missing trusted-copy hint without a generic accept action', () => {
    mockVaultContext.quarantineResolutionById = {
      'item-2': {
        reason: 'missing_on_server',
        canRestore: false,
        canDelete: false,
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

    expect(screen.queryByRole('button', { name: 'Loeschung akzeptieren' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Wiederherstellen' })).not.toBeInTheDocument();
    expect(screen.getByText(/keine verifizierte lokale Kopie/i)).toBeInTheDocument();
  });

  it('calls OpLog restore directly for restorable entries', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-restore': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
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
      expect(mockOpLogRestoreRecord).toHaveBeenCalledWith('item-restore');
    });
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Erfolgreich',
      description: expect.stringContaining('Operation Log'),
    }));
  });

  it('restores only the selected quarantined entry and leaves non-restorable entries untouched', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-restorable': {
        reason: 'ciphertext_changed',
        canRestore: true,
        canDelete: true,
        hasTrustedLocalCopy: true,
        isBusy: false,
        lastError: null,
      },
      'item-not-restorable': {
        reason: 'ciphertext_changed',
        canRestore: false,
        canDelete: true,
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
      expect(mockOpLogRestoreRecord).toHaveBeenCalledWith('item-restorable');
    });
    expect(mockOpLogRestoreRecord).toHaveBeenCalledTimes(1);
    expect(mockOpLogRestoreRecord).not.toHaveBeenCalledWith('item-not-restorable');
  });

  it('confirms deletion for unknown server items and calls the OpLog delete action', async () => {
    mockVaultContext.quarantineResolutionById = {
      'item-3': {
        reason: 'unknown_on_server',
        canRestore: false,
        canDelete: true,
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

    await userEvent.click(screen.getByRole('button', { name: 'Endgueltig loeschen' }));
    expect(screen.getByText('Eintrag endgueltig loeschen?')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Endgueltig loeschen' }));

    await waitFor(() => {
      expect(mockOpLogDeleteUntrustedRecord).toHaveBeenCalledWith('item-3');
    });
    expect(mockToast).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Erfolgreich',
      description: expect.stringContaining('Tombstone'),
    }));
  });
});
