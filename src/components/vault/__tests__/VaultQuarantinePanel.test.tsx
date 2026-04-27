import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { VaultQuarantinePanel } from '../VaultQuarantinePanel';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, options?: { defaultValue?: string; count?: number }) => {
      if (options?.defaultValue && typeof options.count === 'number') {
        return options.defaultValue.replace('{{count}}', String(options.count));
      }
      return options?.defaultValue ?? _key;
    },
  }),
}));

vi.mock('../VaultQuarantineActions', () => ({
  VaultQuarantineActions: ({ item }: { item: { id: string } }) => (
    <div>
      <button type="button">Wiederherstellen {item.id}</button>
      <button type="button">Löschen {item.id}</button>
    </div>
  ),
}));

describe('VaultQuarantinePanel', () => {
  it('summarizes at least two quarantined items and labels authenticator items', () => {
    render(
      <VaultQuarantinePanel
        items={[
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
          { id: 'item-2', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
        ]}
      />,
    );

    expect(screen.getByText('2 betroffene Einträge wurden zusammengefasst.')).toBeInTheDocument();
    expect(screen.getByText('Manipulierter Authenticator-Eintrag')).toBeInTheDocument();
  });

  it('calls the per-entry ignore action for only the selected item', () => {
    const onIgnoreItem = vi.fn();

    render(
      <VaultQuarantinePanel
        items={[
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
          { id: 'item-2', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
        ]}
        onIgnoreItem={onIgnoreItem}
      />,
    );

    fireEvent.click(screen.getAllByRole('button', { name: 'Ignorieren' })[1]);

    expect(onIgnoreItem).toHaveBeenCalledTimes(1);
    expect(onIgnoreItem).toHaveBeenCalledWith(expect.objectContaining({ id: 'item-2' }));
  });

  it('keeps restore and delete actions available for ignored quarantined items', () => {
    render(
      <VaultQuarantinePanel
        items={[]}
        ignoredItems={[
          { id: 'item-ignored', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
        ]}
      />,
    );

    expect(screen.getByText(/Ignorierte Quarant/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Wiederherstellen item-ignored' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Löschen item-ignored' })).toBeInTheDocument();
  });
});
