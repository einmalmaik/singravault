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
        <section id="pwa" className="py-20 bg-gradient-to-br from-primary/5 via-background to-primary/10">
            <div className="container px-4">
                {/* Header */}
                <div className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-4">
                        <Smartphone className="w-4 h-4" />
                        {t('landing.pwa.badge')}
                    </div>
                    <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                        {t('landing.pwa.title')}
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        {t('landing.pwa.subtitle')}
                    </p>
                </div>

                {/* How PWA Works - Feature Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto mb-12">
                    {features.map((feature, index) => (
                        <Card
                            key={feature.key}
                            className="group hover:shadow-lg hover:border-primary/20 transition-all duration-300 animate-fade-in"
                            style={{ animationDelay: `${index * 0.1}s` }}
                        >
                            <CardContent className="p-6">
                                <div className="flex gap-4">
                                    <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center shrink-0 group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                                        <feature.icon className="w-6 h-6" />
                                    </div>
                                    <div>
                                        <h3 className="font-semibold mb-2">
                                            {t(`landing.pwa.features.${feature.key}.title`)}
                                        </h3>
                                        <p className="text-sm text-muted-foreground">
                                            {t(`landing.pwa.features.${feature.key}.description`)}
                                        </p>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    ))}
                </div>

                {/* Security Section */}
                <div className="max-w-4xl mx-auto mb-12">
                    <h3 className="text-2xl font-bold text-center mb-8">
                        {t('landing.pwa.security.title')}
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {securityPoints.map((point, index) => (
                            <Card
                                key={point.key}
                                className="border-green-500/20 bg-green-500/5 hover:border-green-500/40 transition-colors animate-fade-in"
                                style={{ animationDelay: `${(features.length + index) * 0.1}s` }}
                            >
                                <CardContent className="p-6">
                                    <div className="flex gap-4">
                                        <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center shrink-0">
                                            <point.icon className="w-5 h-5 text-green-600 dark:text-green-400" />
                                        </div>
                                        <div>
                                            <h4 className="font-semibold mb-1">
                                                {t(`landing.pwa.security.${point.key}.title`)}
                                            </h4>
                                            <p className="text-sm text-muted-foreground">
                                                {t(`landing.pwa.security.${point.key}.description`)}
                                            </p>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </div>

                {/* Important Notes - Accordion */}
                <div className="max-w-3xl mx-auto">
                    <Card className="border-amber-500/20 bg-amber-500/5">
                        <CardContent className="p-6">
                            <div className="flex items-start gap-3 mb-4">
                                <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                                <h3 className="font-semibold text-amber-800 dark:text-amber-200">
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
                </div>
            </div>
        </section>
    );
}
