// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Settings Page — Open Core Architecture
 *
 * Searchable, filterable settings page. Premium sections are loaded
 * dynamically via the Extension Registry — if no premium package is
 * installed, those sections simply don't appear.
 */

import { useEffect, useState, useMemo } from 'react';
import { useNavigate, Link, useSearchParams } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Settings, ArrowLeft, Shield, Search, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

import { AccountSettings } from '@/components/settings/AccountSettings';
import { SecuritySettings } from '@/components/settings/SecuritySettings';
import { AppearanceSettings } from '@/components/settings/AppearanceSettings';
import { DataSettings } from '@/components/settings/DataSettings';

import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { getExtension, isPremiumActive, getServiceHooks } from '@/extensions/registry';
import type { SettingsSlotProps } from '@/extensions/types';

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
    const [searchParams, setSearchParams] = useSearchParams();
    const { toast } = useToast();
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
        if (searchParams.get('checkout') === 'success') {
            toast({
                title: t('subscription.paymentSuccessful', 'Zahlung erfolgreich!'),
                description: t('subscription.paymentSuccessfulBody', 'Dein Abonnement wurde erfolgreich aktualisiert.'),
            });
            searchParams.delete('checkout');
            setSearchParams(searchParams, { replace: true });
        } else if (searchParams.get('checkout') === 'cancel') {
            toast({
                title: t('subscription.paymentCanceled', 'Zahlung abgebrochen'),
                description: t('subscription.paymentCanceledBody', 'Der Checkout wurde abgebrochen.'),
                variant: 'destructive',
            });
            searchParams.delete('checkout');
            setSearchParams(searchParams, { replace: true });
        }
    }, [searchParams, setSearchParams, t, toast]);

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

            const hooks = getServiceHooks();
            if (!hooks.getTeamAccess) {
                setShowAdminButton(false);
                setIsAdminUser(false);
                return;
            }
            console.debug('[SettingsPage] authReady is true, fetching admin access...');
            const { access, error } = await hooks.getTeamAccess();
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

    // ============ Build Sections (Core + Premium Slots) ============

    const sections: SettingsSection[] = useMemo(() => {
        const result: SettingsSection[] = [
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
        ];

        // --- Premium Slots (only rendered if registered) ---

        const SubscriptionSection = getExtension<SettingsSlotProps>('settings.subscription');
        if (SubscriptionSection) {
            result.push({
                id: 'subscription',
                component: <SubscriptionSection />,
                title: t('subscription.settings_title'),
                keywords: ['subscription', 'billing', 'abonnement', 'zahlung', 'premium', 'families', 'plan'],
            });
        }

        // Account always present (core)
        result.push({
            id: 'account',
            component: <AccountSettings />,
            title: t('settings.account.title'),
            keywords: ['account', 'konto', 'email', 'logout', 'delete', 'löschen'],
        });

        const EmergencySection = getExtension<SettingsSlotProps>('settings.emergency');
        if (EmergencySection) {
            result.push({
                id: 'emergency',
                component: <EmergencySection bypassFeatureGate={isAdminUser} />,
                title: t('emergency.title'),
                keywords: ['emergency', 'notfall', 'trustee', 'recovery', 'wiederherstellung', 'zugriff'],
                premium: true,
            });
        }

        const FamilySection = getExtension<SettingsSlotProps>('settings.family');
        if (FamilySection) {
            result.push({
                id: 'family',
                component: <FamilySection bypassFeatureGate={isAdminUser} />,
                title: t('settings.family.title'),
                keywords: ['family', 'familie', 'organization', 'members', 'mitglieder', 'invite', 'einladen'],
                families: true,
            });
        }

        const SharedCollectionsSection = getExtension<SettingsSlotProps>('settings.shared-collections');
        if (SharedCollectionsSection) {
            result.push({
                id: 'shared-collections',
                component: <SharedCollectionsSection bypassFeatureGate={isAdminUser} />,
                title: t('settings.sharedCollections.title'),
                keywords: ['shared', 'collections', 'geteilt', 'sammlungen', 'share', 'teilen'],
                families: true,
            });
        }

        const SupportSection = getExtension<SettingsSlotProps>('settings.support');
        if (SupportSection) {
            result.push({
                id: 'support',
                component: <SupportSection />,
                title: t('settings.support.title', 'Support'),
                keywords: ['support', 'hilfe', 'help', 'ticket'],
            });
        }

        return result;
    }, [isAdminUser, t]);

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
                        {showAdminButton && isPremiumActive() && (
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
