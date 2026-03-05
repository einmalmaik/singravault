// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 â€” see LICENSE
/**
 * @fileoverview Vault Settings Page
 *
 * Contains vault-specific settings that require an unlocked vault.
 */

import { useEffect, useMemo, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, Shield, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { SecuritySettings } from '@/components/settings/SecuritySettings';
import { DataSettings } from '@/components/settings/DataSettings';
import { useAuth } from '@/contexts/AuthContext';
import { getExtension, getServiceHooks, isPremiumActive } from '@/extensions/registry';
import type { SettingsSlotProps } from '@/extensions/types';

type VaultSettingsSection = {
    id: string;
    component: React.ReactNode;
};

export default function VaultSettingsPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user, authReady } = useAuth();

    const [showAdminButton, setShowAdminButton] = useState(false);
    const [isAdminUser, setIsAdminUser] = useState(false);

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

    const sections: VaultSettingsSection[] = useMemo(() => {
        const result: VaultSettingsSection[] = [
            { id: 'vault-security', component: <SecuritySettings mode="vault" /> },
            { id: 'data', component: <DataSettings /> },
        ];

        const EmergencySection = getExtension<SettingsSlotProps>('settings.emergency');
        if (EmergencySection) {
            result.push({
                id: 'emergency',
                component: <EmergencySection bypassFeatureGate={isAdminUser} />,
            });
        }

        const FamilySection = getExtension<SettingsSlotProps>('settings.family');
        if (FamilySection) {
            result.push({
                id: 'family',
                component: <FamilySection bypassFeatureGate={isAdminUser} />,
            });
        }

        const SharedCollectionsSection = getExtension<SettingsSlotProps>('settings.shared-collections');
        if (SharedCollectionsSection) {
            result.push({
                id: 'shared-collections',
                component: <SharedCollectionsSection bypassFeatureGate={isAdminUser} />,
            });
        }

        return result;
    }, [isAdminUser]);

    return (
        <div className="min-h-screen bg-background">
            <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <div className="container max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
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
                            <Shield className="w-6 h-6 text-primary" />
                            <h1 className="text-xl font-bold">{t('settings.vaultPage.title')}</h1>
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

            <main className="container max-w-4xl mx-auto px-4 py-8">
                <div className="space-y-6">
                    {sections.map((section, index) => (
                        <div key={section.id}>
                            {section.component}
                            {index < sections.length - 1 && <Separator className="mt-6" />}
                        </div>
                    ))}
                </div>

                <div className="mt-12 text-center text-sm text-muted-foreground">
                    <p>Singra Vault v1.0.0</p>
                    <p className="mt-1">{t('settings.footer')}</p>
                </div>
            </main>
        </div>
    );
}
