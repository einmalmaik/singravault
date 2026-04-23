// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Post-Quantum Sharing-Key Protection Settings Component
 * 
 * Displays post-quantum key-wrapping status and security details
 * for Emergency Access and Shared Collections. Vault item payloads
 * remain AES-256-GCM encrypted outside this PQ key-exchange path.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, ShieldCheck, ShieldAlert, ExternalLink, Loader2 } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';

export function PostQuantumSettings() {
    const { t } = useTranslation();
    const { user } = useAuth();

    const [pqEnabled, setPqEnabled] = useState<boolean | null>(null);
    const [pqKeyVersion, setPqKeyVersion] = useState<number | null>(null);
    const [securityStandardVersion, setSecurityStandardVersion] = useState<number | null>(null);
    const [pqEnforcedAt, setPqEnforcedAt] = useState<string | null>(null);
    const [legacyCryptoDisabledAt, setLegacyCryptoDisabledAt] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState(true);

    // Load PQ status on mount
    useEffect(() => {
        async function loadPQStatus() {
            if (!user?.id) return;

            try {
                const { data, error } = await supabase
                    .from('profiles')
                    .select('pq_public_key, pq_key_version, pq_enforced_at, security_standard_version, legacy_crypto_disabled_at')
                    .eq('user_id', user.id)
                    .single();

                if (error) throw error;

                const profile = data as unknown as Record<string, unknown>;
                setPqEnabled(!!profile?.pq_public_key);
                setPqKeyVersion((profile?.pq_key_version as number) || null);
                setSecurityStandardVersion((profile?.security_standard_version as number) || null);
                setPqEnforcedAt((profile?.pq_enforced_at as string) || null);
                setLegacyCryptoDisabledAt((profile?.legacy_crypto_disabled_at as string) || null);
            } catch (err) {
                console.error('Failed to load PQ status:', err);
            } finally {
                setIsLoading(false);
            }
        }

        loadPQStatus();
    }, [user?.id]);

    if (isLoading) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        {t('postQuantum.title')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="flex justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </CardContent>
            </Card>
        );
    }

    const securityStandardActive = !!(
        pqEnabled &&
        securityStandardVersion === 1 &&
        legacyCryptoDisabledAt
    );

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    {pqEnabled ? (
                        <ShieldCheck className="h-5 w-5 text-green-500" />
                    ) : (
                        <ShieldAlert className="h-5 w-5 text-yellow-500" />
                    )}
                    {t('postQuantum.title')}
                </CardTitle>
                <CardDescription>
                    {t('postQuantum.description')}
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                {/* Info Alert */}
                <Alert>
                    <Shield className="h-4 w-4" />
                    <AlertDescription>
                        {t('postQuantum.infoText')}
                    </AlertDescription>
                </Alert>

                {/* Status */}
                <div className="flex items-center justify-between py-2">
                    <span className="text-sm font-medium">{t('postQuantum.status')}</span>
                    <Badge variant={securityStandardActive ? 'default' : 'secondary'}>
                        {securityStandardActive ? t('postQuantum.standardActive') : t('postQuantum.standardPending')}
                    </Badge>
                </div>

                {pqEnabled ? (
                    /* PQ Details when enabled */
                    <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.algorithm')}</span>
                            <span className="font-mono">{t('postQuantum.algorithmValue')}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.keyVersion')}</span>
                            <span className="font-mono">v{pqKeyVersion}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.securityStandard')}</span>
                            <span className="font-mono">
                                {securityStandardVersion ? `v${securityStandardVersion}` : t('postQuantum.notSet')}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.enforcedAt')}</span>
                            <span>
                                {pqEnforcedAt ? new Date(pqEnforcedAt).toLocaleString() : t('postQuantum.notSet')}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.legacyDisabledAt')}</span>
                            <span>
                                {legacyCryptoDisabledAt ? new Date(legacyCryptoDisabledAt).toLocaleString() : t('postQuantum.notSet')}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.securityLevel')}</span>
                            <span>{t('postQuantum.securityLevelValue')}</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">{t('postQuantum.nistStandard')}</span>
                            <Badge variant="outline" className="text-xs">
                                {t('postQuantum.quantumSafe')}
                            </Badge>
                        </div>
                    </div>
                ) : (
                    <p className="text-sm text-muted-foreground">
                        {t('postQuantum.enableDescription')}
                    </p>
                )}

                {/* Learn more link */}
                <a
                    href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                    <ExternalLink className="h-3 w-3" />
                    {t('postQuantum.learnMore')} (NIST FIPS 203)
                </a>
            </CardContent>
        </Card>
    );
}
