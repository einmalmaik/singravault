import type { ReactNode } from 'react';
import { useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { ArrowLeft, Search, Shield, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { isPremiumActive } from '@/extensions/registry';
import type { SettingsSurface, SettingsTabId } from '@/extensions/types';
import { getAdminEntryPath, getPrimaryAppPath, shouldShowWebsiteChrome } from '@/platform/appShell';
import { buildReturnState, resolveReturnPath } from '@/services/returnNavigationState';
import {
  filterSettingsSections,
  getDefaultSettingsTab,
  isSettingsTabId,
  SETTINGS_TABS_BY_SURFACE,
  sortSettingsSections,
} from '@/services/settingsSectionService';

export interface RenderableSettingsSection {
  id: string;
  title: string;
  tab: SettingsTabId;
  order: number;
  keywords: string[];
  content: ReactNode;
}

interface SettingsSurfaceLayoutProps {
  surface: SettingsSurface;
  title: string;
  icon: ReactNode;
  sections: RenderableSettingsSection[];
  backFallbackPath: string;
  showAdminButton: boolean;
}

export function SettingsSurfaceLayout({
  surface,
  title,
  icon,
  sections,
  backFallbackPath,
  showAdminButton,
}: SettingsSurfaceLayoutProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState('');
  const showWebsiteChrome = shouldShowWebsiteChrome();
  const primaryAppPath = getPrimaryAppPath();
  const adminEntryPath = getAdminEntryPath();
  const backTo = resolveReturnPath(location.state, backFallbackPath);
  const allowedTabs = SETTINGS_TABS_BY_SURFACE[surface];
  const availableTabs = useMemo(
    () => allowedTabs.filter((tab) => sections.some((section) => section.tab === tab)),
    [allowedTabs, sections],
  );
  const defaultTab = availableTabs[0] || getDefaultSettingsTab(surface);
  const requestedTab = searchParams.get('tab');
  const activeTab = isSettingsTabId(requestedTab, surface) && availableTabs.includes(requestedTab)
    ? requestedTab
    : defaultTab;

  useEffect(() => {
    if (!location.hash) {
      return;
    }

    const targetId = decodeURIComponent(location.hash.slice(1));
    const target = document.getElementById(targetId);
    if (!target) {
      return;
    }

    window.requestAnimationFrame(() => {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }, [location.hash, searchQuery, activeTab]);

  const sortedSections = useMemo(() => sortSettingsSections(sections), [sections]);
  const filteredSections = useMemo(
    () => filterSettingsSections(sortedSections, searchQuery),
    [searchQuery, sortedSections],
  );

  const visibleSections = searchQuery
    ? filteredSections
    : filteredSections.filter((section) => section.tab === activeTab);

  const groupedSections = useMemo(() => (
    availableTabs.map((tab) => ({
      tab,
      sections: visibleSections.filter((section) => section.tab === tab),
    })).filter((group) => group.sections.length > 0)
  ), [availableTabs, visibleSections]);

  const handleTabChange = (nextTab: string) => {
    if (!isSettingsTabId(nextTab, surface) || !availableTabs.includes(nextTab)) {
      return;
    }

    const nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams.set('tab', nextTab);
    setSearchParams(nextSearchParams, { replace: true });
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-16 max-w-7xl items-center justify-between px-4">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" onClick={() => navigate(backTo)} className="rounded-full">
              <ArrowLeft className="h-5 w-5" />
            </Button>
            <div className="flex items-center gap-2">
              {icon}
              <h1 className="text-xl font-bold">{title}</h1>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {showAdminButton && isPremiumActive() && adminEntryPath && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => navigate(adminEntryPath, { state: buildReturnState(location) })}
                className="flex items-center gap-2"
              >
                <Wrench className="h-4 w-4" />
                <span>{t('admin.title')}</span>
              </Button>
            )}
            {showWebsiteChrome && (
              <Link
                to={primaryAppPath}
                className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-foreground"
              >
                <Shield className="h-5 w-5" />
                <span className="hidden sm:inline font-semibold">Singra Vault</span>
              </Link>
            )}
          </div>
        </div>
      </header>

      <main className="container mx-auto max-w-4xl px-4 py-8">
        <div className="mb-6 space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="search"
              placeholder={t('settings.searchPlaceholder')}
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              className="pl-10"
            />
          </div>

          <Tabs value={activeTab} onValueChange={handleTabChange}>
            <div className="-mx-1 overflow-x-auto px-1 pb-1">
              <TabsList className="inline-flex w-max min-w-full sm:min-w-0">
                {availableTabs.map((tab) => (
                  <TabsTrigger key={tab} value={tab} className="whitespace-nowrap">
                    {getSettingsTabLabel(tab, t)}
                  </TabsTrigger>
                ))}
              </TabsList>
            </div>
          </Tabs>

          {searchQuery && (
            <p className="text-sm text-muted-foreground">
              {t('settings.searchResults', { count: filteredSections.length })}
            </p>
          )}
        </div>

        {groupedSections.length === 0 ? (
          <div className="py-12 text-center">
            <p className="text-muted-foreground">{t('settings.noResults')}</p>
          </div>
        ) : (
          <div className="space-y-8">
            {groupedSections.map((group) => (
              <section key={group.tab} className="space-y-4">
                {searchQuery && (
                  <div className="space-y-2">
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                      {getSettingsTabLabel(group.tab, t)}
                    </h2>
                    <Separator />
                  </div>
                )}

                <div className="space-y-6">
                  {group.sections.map((section) => (
                    <div key={section.id} id={section.id}>
                      {section.content}
                    </div>
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}

        <div className="mt-12 text-center text-sm text-muted-foreground">
          <p>Singra Vault v1.0.0</p>
          <p className="mt-1">{t('settings.footer')}</p>
        </div>
      </main>
    </div>
  );
}

function getSettingsTabLabel(
  tab: SettingsTabId,
  t: TFunction,
): string {
  switch (tab) {
    case 'general':
      return t('settings.tabs.general', 'Allgemein');
    case 'security':
      return t('settings.tabs.security', 'Sicherheit');
    case 'billing-support':
      return t('settings.tabs.billingSupport', 'Abo & Support');
    case 'data':
      return t('settings.tabs.data', 'Daten');
    case 'data-legal':
      return t('settings.tabs.dataLegal', 'Daten & Rechtliches');
    case 'sharing-emergency':
      return t('settings.tabs.sharingEmergency', 'Freigabe & Notfall');
    default:
      return tab;
  }
}
