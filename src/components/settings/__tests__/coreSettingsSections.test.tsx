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

vi.mock('@/components/settings/DeviceKeySettings', () => ({
  DeviceKeySettings: () => null,
}));

import { getCoreProfileSettingsSections, getCoreVaultSettingsSections } from '../coreSettingsSections';

describe('getCoreProfileSettingsSections', () => {
  const t = (key: string, fallback?: string) => fallback ?? key;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('includes legal links when website chrome is visible', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(true);

    const sections = getCoreProfileSettingsSections(t);

    expect(sections.map((section) => section.id)).toContain('profile-legal-links');
  });

  it('also includes legal links in the desktop shell', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(false);

    const sections = getCoreProfileSettingsSections(t);

    expect(sections.map((section) => section.id)).toContain('profile-legal-links');
  });

  it('places legal links under data and legal settings', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(true);

    const sections = getCoreProfileSettingsSections(t);
    const legalLinksSection = sections.find((section) => section.id === 'profile-legal-links');

    expect(legalLinksSection).toMatchObject({
      surface: 'profile',
      tab: 'data-legal',
      order: 20,
    });
    expect(legalLinksSection?.keywords.join(' ')).toContain('datenschutz');
    expect(legalLinksSection?.keywords.join(' ')).toContain('impressum');
    expect(legalLinksSection?.keywords.join(' ')).toContain('whitepaper');
  });

  it('exposes Device Key import from account security without requiring vault settings', () => {
    mockShouldShowWebsiteChrome.mockReturnValue(true);

    const sections = getCoreProfileSettingsSections(t);
    const deviceKeySection = sections.find((section) => section.id === 'profile-device-key');

    expect(deviceKeySection).toMatchObject({
      surface: 'profile',
      tab: 'security',
    });
    expect(deviceKeySection?.keywords.join(' ')).toContain('import');
  });

  it('keeps Device Key management out of vault settings', () => {
    const sections = getCoreVaultSettingsSections(t);

    expect(sections.map((section) => section.id)).not.toContain('profile-device-key');
    expect(sections.flatMap((section) => section.keywords).join(' ')).not.toContain('device key');
  });
});
