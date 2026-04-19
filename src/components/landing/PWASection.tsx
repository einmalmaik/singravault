// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview PWA Technology Section
 * 
 * Explains how the PWA works, its benefits, security, and what users need to know.
 */

import { useTranslation } from 'react-i18next';
import {
    Smartphone,
    Wifi,
    WifiOff,
    Shield,
    Download,
    RefreshCw,
    HardDrive,
    AlertTriangle,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
} from '@/components/ui/accordion';
import { ScrollReveal, ScrollRevealGrid } from '@/components/ScrollReveal';

const features = [
    { key: 'whatIsPwa', icon: Smartphone },
    { key: 'offlineAccess', icon: WifiOff },
    { key: 'installable', icon: Download },
    { key: 'autoSync', icon: RefreshCw },
];

const securityPoints = [
    { key: 'localEncryption', icon: Shield },
    { key: 'offlineCache', icon: HardDrive },
];

export function PWASection() {
    const { t } = useTranslation();

    return (
        <section id="pwa" className="section-dark-alt py-24 overflow-hidden">
            <div className="container px-4">
                {/* Header */}
                <ScrollReveal className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/20 bg-primary/8 text-primary text-sm font-medium mb-4">
                        <Smartphone className="w-4 h-4" />
                        {t('landing.pwa.badge')}
                    </div>
                    <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.pwa.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.pwa.subtitle')}
                    </p>
                </ScrollReveal>

                {/* How PWA Works - Feature Cards */}
                <ScrollRevealGrid
                    className="grid grid-cols-1 md:grid-cols-2 gap-5 max-w-4xl mx-auto mb-12"
                    staggerMs={80}
                >
                    {features.map((feature) => (
                        <Card
                            key={feature.key}
                            className="group border-border/35 bg-card/40 backdrop-blur-sm hover:border-primary/22 hover:bg-card/60 transition-all duration-300"
                        >
                            <CardContent className="p-6">
                                <div className="flex gap-4">
                                    <div className="w-12 h-12 rounded-xl bg-primary/8 border border-primary/12 flex items-center justify-center shrink-0 group-hover:bg-primary group-hover:text-primary-foreground group-hover:border-primary transition-all duration-300">
                                        <feature.icon className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold mb-2 text-foreground/90">
                                            {t(`landing.pwa.features.${feature.key}.title`)}
                                        </h3>
                                        <p className="text-sm text-muted-foreground leading-relaxed">
                                            {t(`landing.pwa.features.${feature.key}.description`)}
                                        </p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    ))}
                </ScrollRevealGrid>

                {/* Security Section */}
                <ScrollReveal delay={100} className="max-w-4xl mx-auto mb-12">
                    <h3 className="text-2xl font-bold text-center mb-8">
                        {t('landing.pwa.security.title')}
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                        {securityPoints.map((point) => (
                            <Card
                                key={point.key}
                                className="border-success/20 bg-success/5 hover:border-success/30 transition-colors"
                            >
                                <CardContent className="p-6">
                                    <div className="flex gap-4">
                                        <div className="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center shrink-0">
                                            <point.icon className="w-5 h-5 text-success" />
                                        </div>
                                        <div>
                                            <h4 className="font-semibold mb-1 text-foreground/90">
                                                {t(`landing.pwa.security.${point.key}.title`)}
                                            </h4>
                                            <p className="text-sm text-muted-foreground leading-relaxed">
                                                {t(`landing.pwa.security.${point.key}.description`)}
                                            </p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </ScrollReveal>

                {/* Important Notes - Accordion */}
                <ScrollReveal delay={150} className="max-w-3xl mx-auto">
                    <Card className="border-warning/20 bg-warning/5">
                        <CardContent className="p-6">
                            <div className="flex items-start gap-3 mb-4">
                                <AlertTriangle className="w-5 h-5 text-warning shrink-0 mt-0.5" />
                                <h3 className="font-semibold text-foreground/90">
                                    {t('landing.pwa.notes.title')}
                                </h3>
                            </div>
                            <Accordion type="single" collapsible className="w-full">
                                <AccordionItem value="firstLogin">
                                    <AccordionTrigger className="text-sm hover:no-underline">
                                        {t('landing.pwa.notes.firstLogin.title')}
                                    </AccordionTrigger>
                                    <AccordionContent className="text-sm text-muted-foreground">
                                        {t('landing.pwa.notes.firstLogin.content')}
                                    </AccordionContent>
                                </AccordionItem>
                                <AccordionItem value="masterPassword">
                                    <AccordionTrigger className="text-sm hover:no-underline">
                                        {t('landing.pwa.notes.masterPassword.title')}
                                    </AccordionTrigger>
                                    <AccordionContent className="text-sm text-muted-foreground">
                                        {t('landing.pwa.notes.masterPassword.content')}
                                    </AccordionContent>
                                </AccordionItem>
                                <AccordionItem value="offlineChanges">
                                    <AccordionTrigger className="text-sm hover:no-underline">
                                        {t('landing.pwa.notes.offlineChanges.title')}
                                    </AccordionTrigger>
                                    <AccordionContent className="text-sm text-muted-foreground">
                                        {t('landing.pwa.notes.offlineChanges.content')}
                                    </AccordionContent>
                                </AccordionItem>
                                <AccordionItem value="browserSupport">
                                    <AccordionTrigger className="text-sm hover:no-underline">
                                        {t('landing.pwa.notes.browserSupport.title')}
                                    </AccordionTrigger>
                                    <AccordionContent className="text-sm text-muted-foreground">
                                        {t('landing.pwa.notes.browserSupport.content')}
                                    </AccordionContent>
                                </AccordionItem>
                            </Accordion>
                        </CardContent>
                    </Card>
                </ScrollReveal>
            </div>
        </section>
    );
}
