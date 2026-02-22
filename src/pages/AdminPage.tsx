// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Admin Page
 *
 * Internal area for support operations and no-code team access management.
 */

import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ArrowLeft, Shield, ShieldAlert, Wrench } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AdminSupportPanel } from '@/components/admin/AdminSupportPanel';
import { AdminTeamPermissionsPanel } from '@/components/admin/AdminTeamPermissionsPanel';
import { useAuth } from '@/contexts/AuthContext';
import { useSubscription } from '@/contexts/SubscriptionContext';

import { getTeamAccess, type TeamAccess } from '@/services/adminService';

export default function AdminPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user, loading, authReady } = useAuth();
    const { billingDisabled } = useSubscription();

    const [access, setAccess] = useState<TeamAccess | null>(null);
    const [isLoadingAccess, setIsLoadingAccess] = useState(true);
    const [accessError, setAccessError] = useState<string | null>(null);

    useEffect(() => {
        if (!loading && !user) {
            navigate('/auth', { replace: true });
        }
    }, [loading, navigate, user]);

    useEffect(() => {
        // Guard: wait for auth to be fully synchronized (token server-validated)
        // Prevents 401s when INITIAL_SESSION sets user before getSession() completes
        if (!user || !authReady) {
            setAccess(null);
            setIsLoadingAccess(false);
            return;
        }

        const loadAccess = async () => {
            setIsLoadingAccess(true);
            setAccessError(null);

            console.debug('[AdminPage] authReady is true, fetching admin access...');
            const { access: accessPayload, error } = await getTeamAccess();
            setIsLoadingAccess(false);

            if (error || !accessPayload) {
                setAccess(null);
                setAccessError(error?.message || t('admin.loadError'));
                return;
            }

            setAccess(accessPayload);
        };

        void loadAccess();
    }, [t, user, authReady]);

    const canSupportTab = useMemo(() => {
        // Subscription permissions are handled in Team tab, not here
        if (!access?.can_access_admin) return false;
        if (!access.permissions.includes('support.admin.access')) return false;
        if (billingDisabled) return false;
        return access.permissions.some(p => [
            'support.tickets.read',
            'support.tickets.reply',
            'support.tickets.reply_internal',
            'support.tickets.status',
            'support.metrics.read',
        ].includes(p));
    }, [access, billingDisabled]);

    const canTeamTab = useMemo(() => {
        // Subscription management lives in Team tab
        if (!access?.can_access_admin) {
            return false;
        }
        return access.permissions.some((permission) =>
            [
                'team.roles.read',
                'team.roles.manage',
                'team.permissions.read',
                'team.permissions.manage',
                'subscriptions.read',
                'subscriptions.manage',
            ].includes(permission),
        );
    }, [access]);

    const defaultTab = canSupportTab ? 'support' : 'team';

    if (loading || isLoadingAccess) {
        return (
            <div className="flex items-center justify-center min-h-screen">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
            </div>
        );
    }

    if (!user) {
        return null;
    }

    if (!access?.can_access_admin || (!canSupportTab && !canTeamTab)) {
        return (
            <div className="min-h-screen bg-background">
                <header className="border-b">
                    <div className="container max-w-6xl mx-auto px-4 h-16 flex items-center gap-3">
                        <Button variant="ghost" size="icon" onClick={() => navigate('/settings')}>
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <div className="flex items-center gap-2">
                            <Shield className="w-5 h-5 text-primary" />
                            <h1 className="text-lg font-semibold">{t('admin.title')}</h1>
                        </div>
                    </div>
                </header>
                <main className="container max-w-3xl mx-auto px-4 py-8">
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <ShieldAlert className="w-5 h-5 text-destructive" />
                                {t('admin.accessDeniedTitle')}
                            </CardTitle>
                            <CardDescription>
                                {accessError || t('admin.accessDeniedDescription')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <Button onClick={() => navigate('/settings')}>{t('admin.backToSettings')}</Button>
                        </CardContent>
                    </Card>
                </main>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-background">
            <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <div className="container max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <Button variant="ghost" size="icon" onClick={() => navigate('/settings')}>
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <div className="flex items-center gap-2">
                            <Wrench className="w-5 h-5 text-primary" />
                            <h1 className="text-lg font-semibold">{t('admin.title')}</h1>
                        </div>
                    </div>
                    <Link
                        to="/"
                        className="flex items-center gap-2 text-muted-foreground hover:text-foreground transition-colors"
                    >
                        <Shield className="w-4 h-4" />
                        <span className="hidden sm:inline text-sm font-medium">{t('admin.brand')}</span>
                    </Link>
                </div>
            </header>

            <main className="container max-w-6xl mx-auto px-4 py-6 space-y-4">
                <Card>
                    <CardHeader>
                        <CardTitle>{t('admin.title')}</CardTitle>
                        <CardDescription>{t('admin.description')}</CardDescription>
                    </CardHeader>
                </Card>

                <Tabs defaultValue={defaultTab} className="space-y-4">
                    <TabsList>
                        {canSupportTab && <TabsTrigger value="support">{t('admin.tabs.support')}</TabsTrigger>}
                        {canTeamTab && <TabsTrigger value="team">{t('admin.tabs.team')}</TabsTrigger>}
                    </TabsList>

                    {canSupportTab && (
                        <TabsContent value="support">
                            <AdminSupportPanel permissions={access.permissions} />
                        </TabsContent>
                    )}

                    {canTeamTab && (
                        <TabsContent value="team">
                            <AdminTeamPermissionsPanel permissions={access.permissions} />
                        </TabsContent>
                    )}
                </Tabs>
            </main>
        </div>
    );
}
