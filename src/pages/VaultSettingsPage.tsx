// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Settings Page
 *
 * Tab-based vault settings surface composed from core descriptors and
 * optional premium descriptors registered through the extension registry.
 */

import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield } from 'lucide-react';

import { SettingsSurfaceLayout, type RenderableSettingsSection } from '@/components/settings/SettingsSurfaceLayout';
import { getCoreVaultSettingsSections } from '@/components/settings/coreSettingsSections';
import { getSettingsSections } from '@/extensions/registry';
import { useAdminPanelAccess } from '@/hooks/use-admin-panel-access';

export default function VaultSettingsPage() {
  const { t } = useTranslation();
  const { isAdminUser, showAdminButton } = useAdminPanelAccess();

  const sections = useMemo<RenderableSettingsSection[]>(() => {
    const descriptors = [
      ...getCoreVaultSettingsSections(t),
      ...getSettingsSections('vault'),
    ];

    return descriptors.map((descriptor) => ({
      id: descriptor.id,
      title: descriptor.title,
      tab: descriptor.tab,
      order: descriptor.order,
      keywords: descriptor.keywords,
      content: descriptor.render({ bypassFeatureGate: isAdminUser }),
    }));
  }, [isAdminUser, t]);

  return (
    <SettingsSurfaceLayout
      surface="vault"
      title={t('settings.vaultPage.title')}
      icon={<Shield className="h-6 w-6 text-primary" />}
      sections={sections}
      backFallbackPath="/vault"
      showAdminButton={showAdminButton}
    />
  );
}
