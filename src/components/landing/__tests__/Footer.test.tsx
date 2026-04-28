// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { Footer } from '../Footer';

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string, params?: Record<string, unknown>) => {
      if (key === 'landing.footer.copyright') return `© ${params?.year} Singra Vault.`;
      return key;
    },
    i18n: { language: 'de' },
  }),
}));

vi.mock('@/i18n', () => ({
  languages: { de: { name: 'Deutsch', flag: 'DE' } },
  changeLanguage: vi.fn(),
}));

vi.mock('@/config/appVersion', () => ({
  APP_VERSION_DISPLAY: 'v1.2.3',
}));

describe('Footer', () => {
  it('shows only the Singra Vault release version in the footer', () => {
    render(
      <MemoryRouter>
        <Footer />
      </MemoryRouter>,
    );

    expect(screen.getByText('Singra Vault Version v1.2.3')).toBeInTheDocument();
    expect(screen.queryByText(/Premium Version/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Core Version/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Whitepaper Version/i)).not.toBeInTheDocument();
  });
});
