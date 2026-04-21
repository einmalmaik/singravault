import type { TFunction } from 'i18next';

import { AccountSettings } from '@/components/settings/AccountSettings';
import { AccountDataExportSettings } from '@/components/settings/AccountDataExportSettings';
import { AppearanceSettings } from '@/components/settings/AppearanceSettings';
import { DataSettings } from '@/components/settings/DataSettings';
import { LegalLinksSettings } from '@/components/settings/LegalLinksSettings';
import { PasswordSettings } from '@/components/settings/PasswordSettings';
import { SecuritySettings } from '@/components/settings/SecuritySettings';
import type { SettingsSectionDescriptor } from '@/extensions/types';
import { shouldShowWebsiteChrome } from '@/platform/appShell';

export function getCoreProfileSettingsSections(t: TFunction): SettingsSectionDescriptor[] {
  const sections: SettingsSectionDescriptor[] = [
    {
      id: 'profile-appearance',
      surface: 'profile',
      tab: 'general',
      order: 10,
      title: t('settings.appearance.title'),
      keywords: ['appearance', 'theme', 'dark', 'light', 'language', 'sprache', 'design', 'aussehen'],
      render: () => <AppearanceSettings />,
    },
    {
      id: 'profile-account',
      surface: 'profile',
      tab: 'general',
      order: 20,
      title: t('settings.account.title'),
      keywords: ['account', 'konto', 'email', 'logout', 'delete', 'loeschen'],
      render: () => <AccountSettings />,
    },
    {
      id: 'profile-two-factor',
      surface: 'profile',
      tab: 'security',
      order: 10,
      title: t('settings.security.title'),
      keywords: ['security', 'sicherheit', '2fa', 'totp', 'authenticator', 'konto-schutz', 'account security'],
      render: () => <SecuritySettings mode="account" />,
    },
    {
      id: 'profile-password',
      surface: 'profile',
      tab: 'security',
      order: 20,
      title: t('settings.password.title'),
      keywords: ['password', 'passwort', 'change password', 'reset password'],
      render: () => <PasswordSettings />,
    },
    {
      id: 'profile-account-export',
      surface: 'profile',
      tab: 'data-legal',
      order: 10,
      title: t('settings.accountDataExport.title'),
      keywords: ['dsgvo', 'gdpr', 'export', 'privacy', 'datenexport', 'account export'],
      render: () => <AccountDataExportSettings />,
    },
  ];

  if (!shouldShowWebsiteChrome()) {
    sections.push({
      id: 'profile-legal-links',
      surface: 'profile',
      tab: 'data-legal',
      order: 20,
      title: t('settings.desktopLegal.title', 'Rechtliches & Informationen'),
      keywords: ['rechtlich', 'privacy', 'datenschutz', 'impressum', 'security', 'whitepaper'],
      render: () => <LegalLinksSettings />,
    });
  }

  return sections;
}

export function getCoreVaultSettingsSections(t: TFunction): SettingsSectionDescriptor[] {
  return [
    {
      id: 'vault-security',
      surface: 'vault',
      tab: 'security',
      order: 10,
      title: t('settings.security.title'),
      keywords: ['vault', 'security', 'auto lock', 'passkey', 'device key', 'tresor', 'sicherheit'],
      render: () => <SecuritySettings mode="vault" />,
    },
    {
      id: 'vault-data',
      surface: 'vault',
      tab: 'data',
      order: 10,
      title: t('settings.data.title', 'Daten'),
      keywords: ['export', 'import', 'backup', 'vault export', 'tresor export', 'tresor import'],
      render: () => <DataSettings />,
    },
  ];
}
