// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Security Features Section
 *
 * Displays the core security features of Singra Vault,
 * including new post-quantum, passkey, duress, and vault integrity capabilities.
 */

import { useTranslation } from 'react-i18next';
import {
    Shield,
    Lock,
    Code,
    Server,
    Atom,
    Fingerprint,
    AlertTriangle,
    ShieldCheck,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';

const features = [
    {
        key: 'zeroKnowledge',
        icon: Shield,
    },
    {
        key: 'e2ee',
        icon: Lock,
    },
    {
        key: 'postQuantum',
        icon: Atom,
    },
    {
        key: 'passkeyUnlock',
        icon: Fingerprint,
    },
    {
        key: 'duressPassword',
        icon: AlertTriangle,
    },
    {
        key: 'vaultIntegrity',
        icon: ShieldCheck,
    },
    {
        key: 'openSource',
        icon: Code,
    },
    {
        key: 'clientSide',
        icon: Server,
    },
];

export function SecurityFeatures() {
    const { t } = useTranslation();

    return (
        <section id="security" className="py-20 bg-muted/50">
            <div className="container px-4">
                <div className="text-center mb-16">
                    <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.security.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.security.subtitle')}
                    </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 max-w-6xl mx-auto">
                    {features.map((feature, index) => (
                        <Card
                            key={feature.key}
                            className="relative overflow-hidden group hover:shadow-lg transition-all duration-300 animate-fade-in"
                            style={{ animationDelay: `${index * 0.1}s` }}
                        >
                            <CardContent className="p-6">
                                {/* Icon */}
                                <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                                    <feature.icon className="w-6 h-6 text-primary" />
                                </div>

                                {/* Title */}
                                <h3 className="text-lg font-semibold mb-2">
                                    {t(`landing.security.${feature.key}.title`)}
                                </h3>

                                {/* Description */}
                                <p className="text-sm text-muted-foreground">
                                    {t(`landing.security.${feature.key}.description`)}
                                </p>

                                {/* Decorative gradient */}
                                <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-primary/0 via-primary to-primary/0 opacity-0 group-hover:opacity-100 transition-opacity" />
                            </CardContent>
                        </Card>
                    ))}
                </div>
            </div>
        </section>
    );
}
