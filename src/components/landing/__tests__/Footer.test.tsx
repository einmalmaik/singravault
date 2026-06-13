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
      if (key === 'landing.footer.poweredBy') return 'Powered by';
      if (key === 'landing.footer.poweredByTooltip') return 'Defensive Integration Shield';
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

  it('shows a "Powered by DIS" attribution with the DIS logo linking to the DIS repo', () => {
    render(
      <MemoryRouter>
        <Footer />
      </MemoryRouter>,
    );

    const disLink = screen.getByRole('link', { name: /Powered by.*Defensive Integration Shield/i });
    expect(disLink).toBeInTheDocument();
    expect(disLink).toHaveAttribute('href', 'https://github.com/einmalmaik/dis');
    expect(disLink).toHaveAttribute('target', '_blank');
    expect(disLink).toHaveAttribute('rel', 'noopener noreferrer');
    expect(disLink).toHaveAttribute('title', 'Defensive Integration Shield');

    const disLogo = screen.getByAltText('DIS') as HTMLImageElement;
    expect(disLogo).toBeInTheDocument();
    expect(disLogo.getAttribute('src')).toBe('/DIS-logo.png');
  });
});
