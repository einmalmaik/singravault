// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Profile Settings Page
 *
 * Tab-based profile settings surface composed from core descriptors and
 * optional premium descriptors registered through the extension registry.
 */

import { useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Settings } from 'lucide-react';

import { SettingsSurfaceLayout, type RenderableSettingsSection } from '@/components/settings/SettingsSurfaceLayout';
import { getCoreProfileSettingsSections } from '@/components/settings/coreSettingsSections';
import { getSettingsSections } from '@/extensions/registry';
import { useAdminPanelAccess } from '@/hooks/use-admin-panel-access';
import { useToast } from '@/hooks/use-toast';
import { getPrimaryAppPath } from '@/platform/appShell';

export default function SettingsPage() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const { isAdminUser, showAdminButton } = useAdminPanelAccess();

  useEffect(() => {
    const checkoutState = searchParams.get('checkout');
    if (!checkoutState) {
      return;
    }

    if (checkoutState === 'success') {
      toast({
        title: t('subscription.paymentSuccessful', 'Zahlung erfolgreich!'),
        description: t(
          'subscription.paymentSuccessfulBody',
          'Dein Abonnement wurde erfolgreich aktualisiert.',
        ),
      });
    } else if (checkoutState === 'cancel') {
      toast({
        title: t('subscription.paymentCanceled', 'Zahlung abgebrochen'),
        description: t('subscription.paymentCanceledBody', 'Der Checkout wurde abgebrochen.'),
        variant: 'destructive',
      });
    }

    const nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams.delete('checkout');
    setSearchParams(nextSearchParams, { replace: true });
  }, [searchParams, setSearchParams, t, toast]);

  const sections = useMemo<RenderableSettingsSection[]>(() => {
    const descriptors = [
      ...getCoreProfileSettingsSections(t),
      ...getSettingsSections('profile'),
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
      surface="profile"
      title={t('settings.accountPage.title')}
      icon={<Settings className="h-6 w-6 text-primary" />}
      sections={sections}
      backFallbackPath={getPrimaryAppPath()}
      showAdminButton={showAdminButton}
    />
  );
}
