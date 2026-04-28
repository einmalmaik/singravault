// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import SecurityWhitepaper from './SecurityWhitepaper';

Object.defineProperty(window, 'scrollTo', {
  value: vi.fn(),
  writable: true,
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    i18n: { language: 'de' },
  }),
}));

vi.mock('@/i18n', () => ({
  languages: { de: { name: 'Deutsch', flag: 'DE' } },
  changeLanguage: vi.fn(),
}));

vi.mock('@/platform/appShell', () => ({
  shouldShowWebsiteChrome: () => false,
}));

vi.mock('@/config/appVersion', () => ({
  APP_VERSION_DISPLAY: 'v1.2.3',
  APP_VERSION_SOURCE: 'github-latest-release',
}));

vi.mock('@/components/SEO', () => ({
  SEO: () => null,
  createArticleStructuredData: () => ({}),
  createBreadcrumbStructuredData: () => ({}),
}));

vi.mock('@/components/layout/DesktopSubpageHeader', () => ({
  DesktopSubpageHeader: ({ title, description }: { title: string; description: string }) => (
    <header>
      <div>{title}</div>
      <div>{description}</div>
    </header>
  ),
}));

describe('SecurityWhitepaper', () => {
  it('renders versioning, audit status, anchors, and claim evidence', () => {
    render(
      <MemoryRouter>
        <SecurityWhitepaper />
      </MemoryRouter>,
    );

    expect(screen.getAllByText('Singra Vault Security Whitepaper')[0]).toBeInTheDocument();
    expect(screen.getByText(/Noch kein externer unabhängiger Security Audit durchgeführt/)).toBeInTheDocument();
    expect(screen.getByText('Whitepaper 2026.04.28-tech-1')).toBeInTheDocument();
    expect(screen.getByText('App v1.2.3')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /6\. Kryptografie/ })).toHaveAttribute('href', '#cryptography');
    expect(screen.getByText('Security Claims Matrix')).toBeInTheDocument();
    expect(screen.getAllByText('NICHT BELEGT').length).toBeGreaterThan(0);
  });
});
