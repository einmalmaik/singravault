import { render, screen } from '@testing-library/react';
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
  VaultQuarantineActions: () => <div>actions</div>,
}));

describe('VaultQuarantinePanel', () => {
  it('summarizes more than two quarantined items and labels authenticator items', () => {
    render(
      <VaultQuarantinePanel
        items={[
          { id: 'item-1', reason: 'ciphertext_changed', updatedAt: null, itemType: 'password' },
          { id: 'item-2', reason: 'ciphertext_changed', updatedAt: null, itemType: 'note' },
          { id: 'item-3', reason: 'ciphertext_changed', updatedAt: null, itemType: 'totp' },
        ]}
      />,
    );

    expect(screen.getByText('3 betroffene Einträge wurden zusammengefasst.')).toBeInTheDocument();
    expect(screen.getByText('Manipulierter Authenticator-Eintrag')).toBeInTheDocument();
  });
});
