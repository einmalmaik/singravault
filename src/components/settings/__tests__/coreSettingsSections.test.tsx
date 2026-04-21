// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockShouldShowWebsiteChrome = vi.fn();

vi.mock('@/platform/appShell', () => ({
  shouldShowWebsiteChrome: () => mockShouldShowWebsiteChrome(),
}));

vi.mock('@/components/settings/AccountSettings', () => ({
  AccountSettings: () => null,
}));

vi.mock('@/components/settings/AccountDataExportSettings', () => ({
  AccountDataExportSettings: () => null,
}));

vi.mock('@/components/settings/AppearanceSettings', () => ({
  AppearanceSettings: () => null,
}));

vi.mock('@/components/settings/DataSettings', () => ({
  DataSettings: () => null,
}));

vi.mock('@/components/settings/LegalLinksSettings', () => ({
  LegalLinksSettings: () => null,
}));

vi.mock('@/components/settings/PasswordSettings', () => ({
  PasswordSettings: () => null,
}));

vi.mock('@/components/settings/SecuritySettings', () => ({
  SecuritySettings: () => null,
}));

import { getCoreProfileSettingsSections } from '../coreSettingsSections';

describe('getCoreProfileSettingsSections', () => {
  const t = (key: string, fallback?: string) => fallback ?? key;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('omits legal links when website chrome is visible', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(true);

    const sections = getCoreProfileSettingsSections(t);

    expect(sections.map((section) => section.id)).not.toContain('profile-legal-links');
  });

  it('includes legal links in the desktop shell', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(false);

    const sections = getCoreProfileSettingsSections(t);

    expect(sections.map((section) => section.id)).toContain('profile-legal-links');
  });
});
