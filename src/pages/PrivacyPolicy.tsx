// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { useTranslation } from 'react-i18next';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Shield, Lock, Eye, Server, Cookie, HelpCircle } from 'lucide-react';
import { Header } from "@/components/landing/Header";
import { Footer } from "@/components/landing/Footer";
import { SEO } from '@/components/SEO';
import { shouldShowWebsiteChrome } from '@/platform/appShell';

const PrivacyPolicy = () => {
    const { t } = useTranslation();
    const showWebsiteChrome = shouldShowWebsiteChrome();

    const sections = [
        {
            id: 'general',
            icon: <Shield className="h-5 w-5 text-primary" />,
            title: t('privacy.general.title'),
            content: t('privacy.general.content')
        },
        {
            id: 'data-collection',
            icon: <Eye className="h-5 w-5 text-primary" />,
            title: t('privacy.collection.title'),
            content: t('privacy.collection.content')
        },
        {
            id: 'security',
            icon: <Lock className="h-5 w-5 text-primary" />,
            title: t('privacy.security.title'),
            content: t('privacy.security.content')
        },
        {
            id: 'storage',
            icon: <Server className="h-5 w-5 text-primary" />,
            title: t('privacy.storage.title'),
            content: t('privacy.storage.content')
        },
        {
            id: 'cookies',
            icon: <Cookie className="h-5 w-5 text-primary" />,
            title: t('privacy.cookies.title'),
            content: t('privacy.cookies.content')
        },
        {
            id: 'rights',
            icon: <HelpCircle className="h-5 w-5 text-primary" />,
            title: t('privacy.rights.title'),
            content: t('privacy.rights.content')
        }
    ];

    return (
        <div className="min-h-screen bg-background flex flex-col">
            <SEO
                title="Datenschutzerklärung"
                description="Datenschutzerklärung von Singra Vault. Erfahre wie wir deine Daten schützen: Zero-Knowledge Architektur, clientseitige Verschlüsselung, keine Weitergabe an Dritte."
                path="/privacy"
                keywords={[
                    'Datenschutz',
                    'Datenschutzerklärung',
                    'Privacy Policy',
                    'DSGVO',
                    'Zero-Knowledge',
                    'Datenverarbeitung',
                ]}
            />
            {showWebsiteChrome && <Header />}
            <main className={`flex-grow flex flex-col items-center px-4 sm:px-6 lg:px-8 ${showWebsiteChrome ? 'py-32' : 'py-10'}`}>
                <div className="w-full max-w-4xl space-y-8">
                    <div className="text-center space-y-4">
                        <h1 className="text-4xl font-bold tracking-tight text-foreground">
                            {t('privacy.title')}
                        </h1>
                        <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                            {t('privacy.subtitle')}
                        </p>
                    </div>

                    <Card className="w-full hover:shadow-lg transition-shadow duration-300">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Shield className="h-6 w-6 text-primary" />
                                {t('privacy.zeroKnowledge.title')}
                            </CardTitle>
                            <CardDescription>
                                {t('privacy.zeroKnowledge.description')}
                            </CardDescription>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <div className="p-4 bg-muted/50 rounded-lg border border-border">
                                <p className="text-sm leading-relaxed">
                                    {t('privacy.zeroKnowledge.details')}
                                </p>
                            </div>
                        </CardContent>
                    </Card>

                    <ScrollArea className="h-full w-full rounded-md">
                        <Accordion type="single" collapsible className="w-full space-y-4">
                            {sections.map((section) => (
                                <AccordionItem key={section.id} value={section.id} className="border-b-0 rounded-lg px-4 bg-card shadow-sm">
                                    <AccordionTrigger className="hover:no-underline py-4">
                                        <div className="flex items-center gap-3">
                                            <div className="p-2 bg-primary/10 rounded-full">
                                                {section.icon}
                                            </div>
                                            <span className="text-lg font-medium">{section.title}</span>
                                        </div>
                                    </AccordionTrigger>
                                    <AccordionContent className="pt-2 pb-4 text-muted-foreground whitespace-pre-line leading-relaxed px-2">
                                        {section.content}
                                    </AccordionContent>
                                </AccordionItem>
                            ))}
                        </Accordion>
                    </ScrollArea>

                    <div className="text-center text-sm text-muted-foreground pt-8 space-y-2">
                        <p>{t('privacy.lastUpdated', { date: new Date().toLocaleDateString() })}</p>
                        <p>{t('privacy.contact')}</p>
                    </div>
                </div>
            </main>
            {showWebsiteChrome && <Footer />}
        </div>
    );
};

export default PrivacyPolicy;
