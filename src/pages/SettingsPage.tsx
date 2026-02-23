// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Settings Page — Redesigned
 *
 * Searchable, filterable settings page with better visual organization
 */

import { useEffect, useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Settings, ArrowLeft, Shield, Search, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

import { AccountSettings } from '@/components/settings/AccountSettings';
import { SecuritySettings } from '@/components/settings/SecuritySettings';
import { AppearanceSettings } from '@/components/settings/AppearanceSettings';
import { DataSettings } from '@/components/settings/DataSettings';
import { SubscriptionSettings } from '@/components/Subscription/SubscriptionSettings';
import EmergencyAccessSettings from '@/components/settings/EmergencyAccessSettings';
import { FamilyOrganizationSettings } from '@/components/settings/FamilyOrganizationSettings';
import { SharedCollectionsSettings } from '@/components/settings/SharedCollectionsSettings';

import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { getTeamAccess } from '@/services/adminService';

type SettingsSection = {
    id: string;
    component: React.ReactNode;
    title: string;
    keywords: string[];
    premium?: boolean;
    families?: boolean;
};

export default function SettingsPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user, loading, authReady } = useAuth();
    const { isLocked } = useVault();

    const [searchQuery, setSearchQuery] = useState('');
    const [showAdminButton, setShowAdminButton] = useState(false);
    const [isAdminUser, setIsAdminUser] = useState(false);

    useEffect(() => {
        if (user && isLocked) {
            navigate('/vault', { replace: true });
        }
    }, [isLocked, user, navigate]);

    useEffect(() => {
        let isCancelled = false;

        const loadAdminAccess = async () => {
            if (!authReady || !user) {
                if (!isCancelled) {
                    setShowAdminButton(false);
                    setIsAdminUser(false);
                }
                return;
            }

            console.debug('[SettingsPage] authReady is true, fetching admin access...');
            const { access, error } = await getTeamAccess();
            if (isCancelled) {
                return;
            }

            if (error || !access) {
                setShowAdminButton(false);
                setIsAdminUser(false);
                return;
            }

            setIsAdminUser(access.is_admin);
            setShowAdminButton(access.can_access_admin);
        };

        void loadAdminAccess();

        return () => {
            isCancelled = true;
        };
    }, [authReady, user]);

    const sections: SettingsSection[] = useMemo(
        () => [
            {
                id: 'appearance',
                component: <AppearanceSettings />,
                title: t('settings.appearance.title'),
                keywords: ['appearance', 'theme', 'dark', 'light', 'language', 'sprache', 'design', 'aussehen'],
            },
            {
                id: 'security',
                component: <SecuritySettings />,
                title: t('settings.security.title'),
                keywords: ['security', 'sicherheit', 'auto-lock', 'lock', 'passwort', 'password', '2fa', 'totp', 'passkey', 'duress'],
            },
            {
                id: 'data',
                component: <DataSettings />,
                title: t('settings.data.title'),
                keywords: ['data', 'daten', 'export', 'import', 'backup', 'sicherung'],
            },
            {
                id: 'subscription',
                component: <SubscriptionSettings />,
                title: t('subscription.settings_title'),
                keywords: ['subscription', 'billing', 'abonnement', 'zahlung', 'premium', 'families', 'plan'],
            },
            {
                id: 'account',
                component: <AccountSettings />,
                title: t('settings.account.title'),
                keywords: ['account', 'konto', 'email', 'logout', 'delete', 'löschen'],
            },
            {
                id: 'emergency',
                component: <EmergencyAccessSettings bypassFeatureGate={isAdminUser} />,
                title: t('emergency.title'),
                keywords: ['emergency', 'notfall', 'trustee', 'recovery', 'wiederherstellung', 'zugriff'],
                premium: true,
            },
            {
                id: 'family',
                component: <FamilyOrganizationSettings bypassFeatureGate={isAdminUser} />,
                title: t('settings.family.title'),
                keywords: ['family', 'familie', 'organization', 'members', 'mitglieder', 'invite', 'einladen'],
                families: true,
            },
            {
                id: 'shared-collections',
                component: <SharedCollectionsSettings bypassFeatureGate={isAdminUser} />,
                title: t('settings.sharedCollections.title'),
                keywords: ['shared', 'collections', 'geteilt', 'sammlungen', 'share', 'teilen'],
                families: true,
            },
        ],
        [isAdminUser, t],
    );

    const filteredSections = useMemo(() => {
        const query = searchQuery.toLowerCase().trim();
        if (!query) {
            return sections;
        }

        return sections.filter((section) => {
            const titleMatch = section.title.toLowerCase().includes(query);
            const keywordMatch = section.keywords.some((kw) => kw.toLowerCase().includes(query));

            return titleMatch || keywordMatch;
        });
    }, [searchQuery, sections]);

    return (
        <div className="min-h-screen bg-background">
            {/* Header */}
            <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <div className="container max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <div className="flex items-center gap-3">
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => navigate('/vault')}
                                className="rounded-full"
                            >
                                <ArrowLeft className="w-5 h-5" />
                            </Button>
                            <div className="flex items-center gap-2">
                                <Settings className="w-6 h-6 text-primary" />
                                <h1 className="text-xl font-bold">{t('settings.title')}</h1>
                            </div>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        {showAdminButton && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => navigate('/admin')}
                                className="flex items-center gap-2"
                            >
                                <Wrench className="w-4 h-4" />
                                <span>{t('admin.title')}</span>
                            </Button>
                        )}
                        <Link
                            to="/"
                            className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
                        >
                            <Shield className="w-5 h-5" />
                            <span className="hidden sm:inline font-semibold">Singra Vault</span>
                        </Link>
                    </div>
                </div>
            </header>

            {/* Main Content */}
            <main className="container max-w-4xl mx-auto px-4 py-8">
                {/* Search Bar */}
                <div className="mb-8">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                            type="search"
                            placeholder={t('settings.searchPlaceholder')}
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="pl-10"
                        />
                    </div>
                    {searchQuery && (
                        <p className="mt-2 text-sm text-muted-foreground">
                            {t('settings.searchResults', { count: filteredSections.length })}
                        </p>
                    )}
                </div>

                {/* Settings Sections */}
                {filteredSections.length === 0 ? (
                    <div className="text-center py-12">
                        <p className="text-muted-foreground">{t('settings.noResults')}</p>
                    </div>
                ) : (
                    <div className="space-y-6">
                        {filteredSections.map((section, index) => (
                            <div key={section.id}>
                                {section.component}
                                {index < filteredSections.length - 1 && <Separator className="mt-6" />}
                            </div>
                        ))}
                    </div>
                )}

                {/* Footer */}
                <div className="mt-12 text-center text-sm text-muted-foreground">
                    <p>Singra Vault v1.0.0</p>
                    <p className="mt-1">{t('settings.footer')}</p>
                </div>
            </main>
        </div>
    );
}
