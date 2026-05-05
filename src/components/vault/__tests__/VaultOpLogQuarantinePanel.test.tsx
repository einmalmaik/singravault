// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { VaultOpLogQuarantinePanel } from '../VaultOpLogQuarantinePanel';
import type { VaultOpLogQuarantinedItemUi } from '@/services/vaultOpLog/vaultOpLogUiAdapter';

describe('VaultOpLogQuarantinePanel', () => {
  const mockItems: VaultOpLogQuarantinedItemUi[] = [
    { recordId: 'item-1', recordState: 'quarantinedTampered', reason: 'tampered' },
    { recordId: 'item-2', recordState: 'quarantinedUnknownAuthor', reason: 'unknown_author' },
    { recordId: 'item-3', recordState: 'quarantinedMissingWithoutDelete', reason: 'missing' },
  ];

  it('renders quarantine panel title', () => {
    render(<VaultOpLogQuarantinePanel items={mockItems} />);
    expect(screen.getByText('Quarantäne')).toBeInTheDocument();
  });

  it('renders each quarantined item without plaintext', () => {
    render(<VaultOpLogQuarantinePanel items={mockItems} />);
    expect(screen.getByText('item-1')).toBeInTheDocument();
    expect(screen.getByText('item-2')).toBeInTheDocument();
    expect(screen.getByText('item-3')).toBeInTheDocument();
    expect(screen.queryByText(/password/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secret/i)).not.toBeInTheDocument();
  });

  it('renders restore and delete buttons when callbacks provided', () => {
    const onRestore = vi.fn();
    const onDelete = vi.fn();
    render(<VaultOpLogQuarantinePanel items={mockItems} onRestore={onRestore} onDelete={onDelete} />);

    const restoreButtons = screen.getAllByText('Wiederherstellen');
    const deleteButtons = screen.getAllByText('Löschen');
    expect(restoreButtons.length).toBe(mockItems.length);
    expect(deleteButtons.length).toBe(mockItems.length);

    fireEvent.click(restoreButtons[0]);
    expect(onRestore).toHaveBeenCalledWith('item-1');

    fireEvent.click(deleteButtons[1]);
    expect(onDelete).toHaveBeenCalledWith('item-2');
  });

  it('does not render buttons when callbacks are omitted', () => {
    render(<VaultOpLogQuarantinePanel items={mockItems} />);
    expect(screen.queryByText('Wiederherstellen')).not.toBeInTheDocument();
    expect(screen.queryByText('Löschen')).not.toBeInTheDocument();
  });

  it('disables restore and delete actions when signed actions are unavailable', () => {
    const onRestore = vi.fn();
    const onDelete = vi.fn();
    render(
      <VaultOpLogQuarantinePanel
        items={mockItems}
        onRestore={onRestore}
        onDelete={onDelete}
        actionsDisabled
      />,
    );

    const restoreButton = screen.getAllByText('Wiederherstellen')[0].closest('button');
    const deleteButton = screen.getAllByText(/schen$/)[0].closest('button');
    expect(restoreButton).toBeDisabled();
    expect(deleteButton).toBeDisabled();
    fireEvent.click(restoreButton!);
    fireEvent.click(deleteButton!);
    expect(onRestore).not.toHaveBeenCalled();
    expect(onDelete).not.toHaveBeenCalled();
  });

  it('returns null for empty items', () => {
    const { container } = render(<VaultOpLogQuarantinePanel items={[]} />);
    expect(container.firstChild).toBeNull();
  });
});
