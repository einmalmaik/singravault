// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { VaultOpLogConflictPanel } from '../VaultOpLogConflictPanel';
import type { VaultOpLogConflictUi } from '@/services/vaultOpLog/vaultOpLogUiAdapter';

describe('VaultOpLogConflictPanel', () => {
  const mockItems: VaultOpLogConflictUi[] = [
    { recordId: 'item-1', operationCount: 2, operationIds: ['op-1', 'op-2'] },
    { recordId: 'item-2', operationCount: 3, operationIds: ['op-3', 'op-4', 'op-5'] },
  ];

  it('renders conflict panel title', () => {
    render(<VaultOpLogConflictPanel items={mockItems} />);
    expect(screen.getByText('Konflikte')).toBeInTheDocument();
  });

  it('renders each conflict without plaintext', () => {
    render(<VaultOpLogConflictPanel items={mockItems} />);
    expect(screen.getByText('item-1')).toBeInTheDocument();
    expect(screen.getByText('item-2')).toBeInTheDocument();
    expect(screen.queryByText(/password/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secret/i)).not.toBeInTheDocument();
  });

  it('renders operation count and IDs', () => {
    render(<VaultOpLogConflictPanel items={mockItems} />);
    // i18next is not initialized in tests, so interpolation variables are not replaced.
    const operationLabels = screen.getAllByText('{{count}} Operationen');
    expect(operationLabels.length).toBe(mockItems.length);
    expect(screen.getByText('op-1, op-2')).toBeInTheDocument();
  });

  it('renders resolve button when callback provided', () => {
    const onResolve = vi.fn();
    render(<VaultOpLogConflictPanel items={mockItems} onResolve={onResolve} />);

    const resolveButtons = screen.getAllByText('Auflösen');
    expect(resolveButtons.length).toBe(mockItems.length);

    fireEvent.click(resolveButtons[0]);
    expect(onResolve).toHaveBeenCalledWith('item-1');
  });

  it('does not render resolve button when callback is omitted', () => {
    render(<VaultOpLogConflictPanel items={mockItems} />);
    expect(screen.queryByText('Auflösen')).not.toBeInTheDocument();
  });

  it('disables resolve action when signed action is unavailable', () => {
    const onResolve = vi.fn();
    render(<VaultOpLogConflictPanel items={mockItems} onResolve={onResolve} actionsDisabled />);

    const resolveButton = screen.getAllByText(/sen$/)[0].closest('button');
    expect(resolveButton).toBeDisabled();
    fireEvent.click(resolveButton!);
    expect(onResolve).not.toHaveBeenCalled();
  });

  it('returns null for empty items', () => {
    const { container } = render(<VaultOpLogConflictPanel items={[]} />);
    expect(container.firstChild).toBeNull();
  });
});
