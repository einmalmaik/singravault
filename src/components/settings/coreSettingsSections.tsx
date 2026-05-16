import type { TFunction } from 'i18next';

import { AccountSettings } from '@/components/settings/AccountSettings';
import { AccountDataExportSettings } from '@/components/settings/AccountDataExportSettings';
import { AppearanceSettings } from '@/components/settings/AppearanceSettings';
import { DataSettings } from '@/components/settings/DataSettings';
import { LegacyDuressDecoyCleanupSettings } from '@/components/settings/LegacyDuressDecoyCleanupSettings';
import { LegalLinksSettings } from '@/components/settings/LegalLinksSettings';
import { PasswordSettings } from '@/components/settings/PasswordSettings';
import { SecuritySettings } from '@/components/settings/SecuritySettings';
import { DeviceKeySettings } from '@/components/settings/DeviceKeySettings';
import { TrustedDevicesSettings } from '@/components/settings/TrustedDevicesSettings';
import { VaultRecoveryCodesSettings } from '@/components/settings/VaultRecoveryCodesSettings';
import type { SettingsSectionDescriptor } from '@/extensions/types';

export function getCoreProfileSettingsSections(t: TFunction): SettingsSectionDescriptor[] {
  return [
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
      keywords: ['account', 'konto', 'email', 'logout', 'delete', 'löschen', 'loeschen'],
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
      id: 'profile-device-key',
      surface: 'profile',
      tab: 'security',
      order: 30,
      title: t('deviceKey.title'),
      keywords: ['device key', 'geräte-schlüssel', 'geraeteschluessel', 'import', 'transfer', 'gerät autorisieren'],
      render: () => <DeviceKeySettings />,
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
    {
      id: 'profile-legal-links',
      surface: 'profile',
      tab: 'data-legal',
      order: 20,
      title: t('settings.desktopLegal.title', 'Rechtliches & Informationen'),
      keywords: ['rechtlich', 'privacy', 'datenschutz', 'impressum', 'security', 'whitepaper'],
      render: () => <LegalLinksSettings />,
    },
    {
      id: 'profile-legacy-duress-cleanup',
      // PROFILE surface (not vault) on purpose: the recovery flow has to
      // be reachable while the vault is still in the
      // `integrityMode === 'migration_required'` state, which means
      // /vault/settings is unreachable. Account/profile settings are the
      // only place that stays open for an authenticated user with a
      // locked vault.
      surface: 'profile',
      tab: 'data-legal',
      order: 30,
      title: 'Tresor-Reparatur',
      keywords: [
        'tresor reparatur', 'tresor-reparatur', 'reparatur',
        'panik-passwort', 'panik passwort', 'panic password',
        'duress', 'duress decoy', 'koeder', 'köder',
        'migration erforderlich', 'migration required',
        'orphan', 'integrity_unknown',
      ],
      render: () => <LegacyDuressDecoyCleanupSettings />,
    },
  ];
}

export function getCoreVaultSettingsSections(t: TFunction): SettingsSectionDescriptor[] {
  return [
    {
      id: 'vault-security',
      surface: 'vault',
      tab: 'security',
      order: 10,
      title: t('settings.security.title'),
      keywords: ['vault', 'security', 'auto lock', 'passkey', 'tresor', 'sicherheit'],
      render: () => <SecuritySettings mode="vault" />,
    },
    {
      id: 'vault-trusted-devices',
      surface: 'vault',
      tab: 'security',
      order: 20,
      title: 'Vertrauenswürdige Geräte',
      keywords: ['device trust', 'geräte', 'geraete', 'trusted device', 'freigabe', 'autorisiert', 'entfernen'],
      render: () => <TrustedDevicesSettings />,
    },
    {
      id: 'vault-recovery-codes',
      surface: 'vault',
      tab: 'security',
      order: 30,
      title: 'Recovery-Codes',
      keywords: ['recovery', 'backup codes', 'geräte recovery', 'geraete recovery', 'wiederherstellung', 'notfall', 'device trust'],
      render: () => <VaultRecoveryCodesSettings />,
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
