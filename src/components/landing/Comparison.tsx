// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Comparison Table Section
 *
 * Compares Singra Vault with other password managers.
 * All competitor data is based on publicly available information
 * from official documentation (verified Feb 2026).
 *
 * Sources:
 * - Bitwarden: bitwarden.com/help/kdf-algorithms/, bitwarden.com/pricing/
 * - 1Password: 1password.com/pricing, support.1password.com
 * - LastPass: lastpass.com/pricing, support.lastpass.com
 */

import { useTranslation } from 'react-i18next';
import { Check, X, Minus, Shield } from 'lucide-react';
import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from '@/components/ui/table';

type FeatureStatus = 'yes' | 'no' | 'partial';

interface Competitor {
    name: string;
    features: Record<string, FeatureStatus>;
    details: Record<string, string>;
}

const competitors: Competitor[] = [
    {
        name: 'Singra Vault',
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
            pricing: '€0 / €1,65/mo',
            loginProtocol: 'OPAQUE (IETF PAKE)',
            deviceKey: '256-bit HKDF',
        },
    },
    {
        name: 'Bitwarden',
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
            clipboardClear: '10–300s',
            pricing: '$0 / <$1/mo',
            loginProtocol: 'Passwort über TLS',
        },
    },
    {
        name: '1Password',
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
            pricing: '$2.99/mo',
            loginProtocol: 'SRP',
            deviceKey: '128-bit Secret Key',
        },
    },
    {
        name: 'LastPass',
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
            pricing: '$3/mo',
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
        <section id="comparison" className="py-20">
            <div className="container px-4">
                <div className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 rounded-full bg-primary/10 px-4 py-1.5 text-sm font-medium text-primary mb-4">
                        <Shield className="w-4 h-4" />
                        {t('landing.comparison.badge')}
                    </div>
                    <h2 className="text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.comparison.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.comparison.subtitle')}
                    </p>
                </div>

                <div className="max-w-5xl mx-auto overflow-x-auto">
                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead className="w-[220px]">
                                    {t('landing.comparison.featureLabel')}
                                </TableHead>
                                {competitors.map((c) => (
                                    <TableHead key={c.name} className="text-center min-w-[120px]">
                                        <span className={c.name === 'Singra Vault' ? 'text-primary font-bold' : ''}>
                                            {c.name}
                                        </span>
                                    </TableHead>
                                ))}
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {featureKeys.map((featureKey) => (
                                <TableRow key={featureKey}>
                                    <TableCell className="font-medium">
                                        {t(`landing.comparison.features.${featureKey}`)}
                                    </TableCell>
                                    {competitors.map((c) => (
                                        <TableCell key={`${c.name}-${featureKey}`} className="text-center">
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
                </div>

                {/* Legend */}
                <div className="flex justify-center gap-6 mt-6 text-sm text-muted-foreground">
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
                </div>

                <p className="text-center text-xs text-muted-foreground mt-4 max-w-2xl mx-auto">
                    {t('landing.comparison.disclaimer')}
                </p>
            </div>
        </section>
    );
}

