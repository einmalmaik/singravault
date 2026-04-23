// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Comparison Table Section
 *
 * Compares Singra Vault with other password managers.
 * All competitor data is based on publicly available information
 * from official documentation (verified Apr 23, 2026).
 */

import { useTranslation } from 'react-i18next';
import { Check, X, Minus, Shield, ExternalLink } from 'lucide-react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';
import { ScrollReveal } from '@/components/ScrollReveal';

type FeatureStatus = 'yes' | 'no' | 'partial';

interface Competitor {
    name: string;
    verifiedAt: string;
    sourceUrls: string[];
    features: Record<string, FeatureStatus>;
    details: Record<string, string>;
}

const competitors: Competitor[] = [
    {
        name: 'Singra Vault',
        verifiedAt: '2026-04-23',
        sourceUrls: [
            'https://singravault.mauntingstudios.de/',
            'https://singravault.mauntingstudios.de/security',
        ],
        features: {
            openSource: 'yes',
            e2ee: 'yes',
            zeroKnowledge: 'yes',
            free: 'yes',
            kdf: 'yes',
            postQuantum: 'yes',
            passkeyUnlock: 'yes',
            duressPassword: 'yes',
            vaultIntegrity: 'yes',
            clipboardClear: 'yes',
            totp: 'yes',
            pricing: 'yes',
            loginProtocol: 'yes',
            deviceKey: 'yes',
        },
        details: {
            kdf: 'Argon2id 128 MiB',
            postQuantum: 'Security Standard v1 (ML-KEM-768 + RSA-4096 hybrid for sharing/emergency)',
            clipboardClear: '30s',
            pricing: '€0 / €1,65 pro Monat',
            loginProtocol: 'OPAQUE (IETF PAKE)',
            deviceKey: '256-bit HKDF',
        },
    },
    {
        name: 'Bitwarden',
        verifiedAt: '2026-04-23',
        sourceUrls: [
            'https://bitwarden.com/products/personal/',
            'https://bitwarden.com/help/kdf-algorithms/',
            'https://bitwarden.com/help/login-with-passkeys/',
        ],
        features: {
            openSource: 'yes',
            e2ee: 'yes',
            zeroKnowledge: 'yes',
            free: 'yes',
            kdf: 'partial',
            postQuantum: 'no',
            passkeyUnlock: 'partial',
            duressPassword: 'no',
            vaultIntegrity: 'no',
            clipboardClear: 'yes',
            totp: 'partial',
            pricing: 'partial',
            loginProtocol: 'no',
            deviceKey: 'no',
        },
        details: {
            kdf: 'PBKDF2 600K / Argon2id 64 MiB',
            clipboardClear: '10-300s',
            pricing: '$0 / $10 pro Jahr',
            loginProtocol: 'Passwort über TLS',
        },
    },
    {
        name: '1Password',
        verifiedAt: '2026-04-23',
        sourceUrls: [
            'https://1password.com/affiliate/individual-families',
            'https://support.1password.com/passkeys/',
        ],
        features: {
            openSource: 'no',
            e2ee: 'yes',
            zeroKnowledge: 'yes',
            free: 'no',
            kdf: 'partial',
            postQuantum: 'no',
            passkeyUnlock: 'yes',
            duressPassword: 'no',
            vaultIntegrity: 'no',
            clipboardClear: 'yes',
            totp: 'yes',
            pricing: 'no',
            loginProtocol: 'partial',
            deviceKey: 'partial',
        },
        details: {
            kdf: 'PBKDF2 + Secret Key',
            clipboardClear: '90s',
            pricing: '$2.99 pro Monat',
            loginProtocol: 'SRP',
            deviceKey: '128-bit Secret Key',
        },
    },
    {
        name: 'LastPass',
        verifiedAt: '2026-04-23',
        sourceUrls: [
            'https://www.lastpass.com/pricing',
            'https://www.lastpass.com/features/passkeys',
        ],
        features: {
            openSource: 'no',
            e2ee: 'yes',
            zeroKnowledge: 'yes',
            free: 'partial',
            kdf: 'partial',
            postQuantum: 'no',
            passkeyUnlock: 'yes',
            duressPassword: 'no',
            vaultIntegrity: 'no',
            clipboardClear: 'yes',
            totp: 'partial',
            pricing: 'partial',
            loginProtocol: 'no',
            deviceKey: 'no',
        },
        details: {
            kdf: 'PBKDF2 600K',
            pricing: '$3.00 pro Monat',
            loginProtocol: 'Passwort über TLS',
        },
    },
];

const featureKeys = [
    'openSource',
    'e2ee',
    'zeroKnowledge',
    'kdf',
    'deviceKey',
    'loginProtocol',
    'postQuantum',
    'passkeyUnlock',
    'duressPassword',
    'vaultIntegrity',
    'clipboardClear',
    'totp',
    'free',
    'pricing',
];

function StatusIcon({ status }: { status: FeatureStatus }) {
    switch (status) {
        case 'yes':
            return <Check className="w-5 h-5 text-success mx-auto" />;
        case 'no':
            return <X className="w-5 h-5 text-destructive mx-auto" />;
        case 'partial':
            return <Minus className="w-5 h-5 text-warning mx-auto" />;
    }
}

export function Comparison() {
    const { t } = useTranslation();

    return (
        <section id="comparison" className="section-dark-alt py-24 overflow-hidden">
            <div className="container px-4">
                <ScrollReveal className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-4 py-1.5 text-sm font-medium text-primary mb-4">
                        <Shield className="w-4 h-4" />
                        {t('landing.comparison.badge')}
                    </div>
                    <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.comparison.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.comparison.subtitle')}
                    </p>
                </ScrollReveal>

                <ScrollReveal delay={100} className="max-w-5xl mx-auto overflow-x-auto rounded-2xl border border-border/35 bg-card/30 backdrop-blur-sm p-1">
                    <Table>
                        <TableHeader>
                            <TableRow className="border-border/40 hover:bg-transparent">
                                <TableHead className="w-[220px] text-muted-foreground/80">
                                    {t('landing.comparison.featureLabel')}
                                </TableHead>
                                {competitors.map((c) => (
                                    <TableHead key={c.name} className={`text-center min-w-[120px] ${c.name === 'Singra Vault' ? 'bg-primary/6 rounded-t-lg' : ''}`}>
                                        <span className={c.name === 'Singra Vault' ? 'text-primary font-bold' : 'text-muted-foreground'}>
                                            {c.name}
                                        </span>
                                    </TableHead>
                                ))}
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {featureKeys.map((featureKey) => (
                                <TableRow key={featureKey} className="border-border/25 hover:bg-card/40 transition-colors">
                                    <TableCell className="font-medium text-foreground/80">
                                        {t(`landing.comparison.features.${featureKey}`)}
                                    </TableCell>
                                    {competitors.map((c) => (
                                        <TableCell key={`${c.name}-${featureKey}`} className={`text-center ${c.name === 'Singra Vault' ? 'bg-primary/4' : ''}`}>
                                            {c.details[featureKey] ? (
                                                <div className="flex flex-col items-center gap-0.5">
                                                    <StatusIcon status={c.features[featureKey]} />
                                                    <span className="text-[10px] text-muted-foreground leading-tight">
                                                        {c.details[featureKey]}
                                                    </span>
                                                </div>
                                            ) : (
                                                <StatusIcon status={c.features[featureKey]} />
                                            )}
                                        </TableCell>
                                    ))}
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </ScrollReveal>

                <ScrollReveal delay={200} className="flex justify-center gap-6 mt-6 text-sm text-muted-foreground">
                    <div className="flex items-center gap-2">
                        <Check className="w-4 h-4 text-success" />
                        <span>{t('landing.comparison.legend.full')}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <Minus className="w-4 h-4 text-warning" />
                        <span>{t('landing.comparison.legend.partial')}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <X className="w-4 h-4 text-destructive" />
                        <span>{t('landing.comparison.legend.unavailable')}</span>
                    </div>
                </ScrollReveal>

                <p className="text-center text-xs text-muted-foreground mt-4 max-w-2xl mx-auto">
                    {t('landing.comparison.disclaimer')}
                </p>

                <div className="mt-4 flex flex-col gap-2 text-xs text-muted-foreground">
                    {competitors.map((competitor) => (
                        <div key={competitor.name} className="rounded-lg border border-border/35 bg-card/20 px-3 py-2">
                            <span className="font-medium text-foreground/80">{competitor.name}</span>{' '}
                            <span>{t('landing.comparison.verifiedAt', {
                                defaultValue: 'Stand: {{date}}',
                                date: competitor.verifiedAt,
                            })}</span>
                            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                                {competitor.sourceUrls.map((url) => (
                                    <a
                                        key={url}
                                        href={url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-flex items-center gap-1 hover:text-foreground"
                                    >
                                        <ExternalLink className="h-3 w-3" />
                                        {url.replace(/^https?:\/\//, '')}
                                    </a>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </section>
    );
}
