// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Account Data Export Settings
 *
 * Provides a GDPR/DSGVO-focused account data export for machine-readable download.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Download, FileJson, Loader2, ShieldCheck } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';
import { isPremiumActive } from '@/extensions/registry';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';
import { toExportSubscriptionSnapshot } from '@/services/subscriptionExportStatusService';
import { saveExportFile } from '@/services/exportFileService';

export function AccountDataExportSettings() {
    const { t } = useTranslation();
    const { user } = useAuth();
    const { toast } = useToast();

    const [isExporting, setIsExporting] = useState(false);
    const includePremiumSubscriptionData = isPremiumActive();

    const handleAccountExport = async () => {
        if (!user) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('auth.errors.invalidCredentials'),
            });
            return;
        }

        setIsExporting(true);
        try {
            const [profileResult, subscriptionResult, twoFactorResult, passkeysResult, backupCodesResult] = await Promise.all([
                supabase.from('profiles').select('*').eq('id', user.id).maybeSingle(),
                includePremiumSubscriptionData
                    ? supabase.from('subscriptions').select('*').eq('user_id', user.id).maybeSingle()
                    : Promise.resolve({ data: null, error: null }),
                supabase.from('user_2fa').select('*').eq('user_id', user.id).maybeSingle(),
                supabase
                    .from('passkey_credentials')
                    .select('id, device_name, created_at, last_used_at, prf_enabled, transports, aaguid')
                    .eq('user_id', user.id),
                supabase.from('backup_codes').select('id, is_used, created_at, used_at').eq('user_id', user.id),
            ]);

            const warnings = [
                ...asWarning('profile_unavailable', profileResult.error),
                ...asWarning('subscription_unavailable', includePremiumSubscriptionData ? subscriptionResult.error : null),
                ...asWarning('two_factor_unavailable', twoFactorResult.error),
                ...asWarning('passkeys_unavailable', passkeysResult.error),
                ...asWarning('backup_codes_unavailable', backupCodesResult.error),
            ];

            const profile = profileResult.data ? sanitizeProfile(profileResult.data) : null;
            const subscription = includePremiumSubscriptionData && subscriptionResult.data
                ? toExportSubscriptionSnapshot(subscriptionResult.data)
                : null;
            const twoFactor = twoFactorResult.data ? sanitizeTwoFactor(twoFactorResult.data) : null;
            const passkeys = (passkeysResult.data || []).map((item) => ({
                id: item.id,
                device_name: item.device_name,
                created_at: item.created_at,
                last_used_at: item.last_used_at,
                prf_enabled: item.prf_enabled,
                transports: item.transports,
                aaguid: item.aaguid,
            }));
            const backupCodes = summarizeBackupCodes(backupCodesResult.data || []);

            const exportData = {
                version: '1.0',
                exportType: 'account-data',
                exportedAt: new Date().toISOString(),
                user: {
                    id: user.id,
                    email: user.email || null,
                    phone: user.phone || null,
                    created_at: user.created_at || null,
                    last_sign_in_at: user.last_sign_in_at || null,
                    app_metadata: user.app_metadata || {},
                    user_metadata: user.user_metadata || {},
                },
                account: {
                    profile,
                    subscription,
                },
                security: {
                    two_factor: twoFactor,
                    passkeys,
                    backup_codes: backupCodes,
                },
                warnings,
            };

            const saved = await saveExportFile({
                name: `singra-account-data-export-${new Date().toISOString().split('T')[0]}.json`,
                mime: 'application/json',
                content: JSON.stringify(exportData, null, 2),
            });

            if (!saved) {
                return;
            }

            toast({
                title: t('common.success'),
                description: t('settings.accountDataExport.exportSuccess'),
            });
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.accountDataExport.exportFailed'),
            });
        } finally {
            setIsExporting(false);
        }
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5" />
                    {t('settings.accountDataExport.title')}
                </CardTitle>
                <CardDescription>
                    {t('settings.accountDataExport.description')}
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
                <Label className="flex items-center gap-2">
                    <Download className="w-4 h-4" />
                    {t('settings.accountDataExport.export')}
                </Label>
                <p className="text-sm text-muted-foreground">
                    {t('settings.accountDataExport.exportDesc')}
                </p>
                <Button
                    variant="outline"
                    onClick={handleAccountExport}
                    disabled={isExporting}
                    className="flex items-center gap-2"
                >
                    {isExporting ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                        <FileJson className="w-4 h-4" />
                    )}
                    {t('settings.accountDataExport.exportButton')}
                </Button>
            </CardContent>
        </Card>
    );
}

function asWarning(code: string, error: unknown): string[] {
    if (error) {
        return [code];
    }
    return [];
}

function summarizeBackupCodes(
    rows: Pick<Database['public']['Tables']['backup_codes']['Row'], 'id' | 'is_used' | 'created_at' | 'used_at'>[],
): { total: number; used: number; unused: number; created_at: string | null; last_used_at: string | null } {
    const used = rows.filter((row) => row.is_used === true).length;
    const createdAtValues = rows
        .map((row) => row.created_at)
        .filter((value): value is string => typeof value === 'string')
        .sort();
    const lastUsedValues = rows
        .map((row) => row.used_at)
        .filter((value): value is string => typeof value === 'string')
        .sort();

    return {
        total: rows.length,
        used,
        unused: Math.max(0, rows.length - used),
        created_at: createdAtValues[0] || null,
        last_used_at: lastUsedValues[lastUsedValues.length - 1] || null,
    };
}

function sanitizeTwoFactor(
    row: Database['public']['Tables']['user_2fa']['Row'],
): {
    user_id: string;
    is_enabled: boolean | null;
    vault_2fa_enabled: boolean | null;
    enabled_at: string | null;
    last_verified_at: string | null;
    created_at: string | null;
    updated_at: string | null;
} {
    return {
        user_id: row.user_id,
        is_enabled: row.is_enabled,
        vault_2fa_enabled: row.vault_2fa_enabled,
        enabled_at: row.enabled_at,
        last_verified_at: row.last_verified_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    };
}

function sanitizeProfile(
    row: Database['public']['Tables']['profiles']['Row'],
): {
    id: string;
    user_id: string;
    auth_protocol: string;
    display_name: string | null;
    avatar_url: string | null;
    preferred_language: string | null;
    theme: string | null;
    hide_community_ads: boolean | null;
    kdf_version: number;
    duress_kdf_version: number | null;
    pq_key_version: number | null;
    pq_public_key: string | null;
    pq_enforced_at: string | null;
    security_standard_version: number | null;
    legacy_crypto_disabled_at: string | null;
    created_at: string;
    updated_at: string;
} {
    return {
        id: row.id,
        user_id: row.user_id,
        auth_protocol: row.auth_protocol,
        display_name: row.display_name,
        avatar_url: row.avatar_url,
        preferred_language: row.preferred_language,
        theme: row.theme,
        hide_community_ads: row.hide_community_ads,
        kdf_version: row.kdf_version,
        duress_kdf_version: row.duress_kdf_version,
        pq_key_version: row.pq_key_version,
        pq_public_key: row.pq_public_key,
        pq_enforced_at: row.pq_enforced_at,
        security_standard_version: row.security_standard_version,
        legacy_crypto_disabled_at: row.legacy_crypto_disabled_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    };
}
