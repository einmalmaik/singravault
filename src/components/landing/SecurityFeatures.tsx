// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Security Features Section
 *
 * Displays the core security features of Singra Vault,
 * including post-quantum sharing-key protection, passkey, duress, and vault integrity capabilities.
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
import { ScrollReveal, ScrollRevealGrid } from '@/components/ScrollReveal';

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
        <section id="security" className="section-dark-alt py-24 overflow-hidden">
            <div className="container px-4">
                <ScrollReveal className="text-center mb-16">
                    <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.security.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.security.subtitle')}
                    </p>
                </ScrollReveal>

                <ScrollRevealGrid
                    className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 max-w-6xl mx-auto"
                    staggerMs={70}
                >
                    {features.map((feature) => (
                        <Card
                            key={feature.key}
                            className="relative overflow-hidden group border-border/40 bg-card/50 backdrop-blur-sm hover:border-primary/25 hover:bg-card/70 transition-all duration-300"
                        >
                            <CardContent className="p-6">
                                {/* Icon */}
                                <div className="w-12 h-12 rounded-xl bg-primary/8 border border-primary/12 flex items-center justify-center mb-4 group-hover:bg-primary/16 group-hover:border-primary/22 transition-all duration-300">
                                    <feature.icon className="w-6 h-6 text-primary" />
                                </div>

                                {/* Title */}
                                <h3 className="text-base font-semibold mb-2 text-foreground/90">
                                    {t(`landing.security.${feature.key}.title`)}
                                </h3>

                                {/* Description */}
                                <p className="text-sm text-muted-foreground leading-relaxed">
                                    {t(`landing.security.${feature.key}.description`)}
                                </p>

                                {/* Decorative gradient */}
                                <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                            </CardContent>
                        </Card>
                    ))}
                </ScrollRevealGrid>
            </div>
        </section>
    );
}
