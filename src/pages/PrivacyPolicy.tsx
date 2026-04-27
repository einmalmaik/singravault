// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { Cookie, Eye, HelpCircle, Lock, Server, Shield } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Footer } from "@/components/landing/Footer";
import { Header } from "@/components/landing/Header";
import { DesktopSubpageFrame } from "@/components/layout/DesktopSubpageFrame";
import { SEO } from "@/components/SEO";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { shouldShowWebsiteChrome } from "@/platform/appShell";

function PrivacyPolicyContent() {
  const { t } = useTranslation();

  const sections = [
    {
      id: "general",
      icon: <Shield className="h-5 w-5 text-primary" />,
      title: t("privacy.general.title"),
      content: t("privacy.general.content"),
    },
    {
      id: "data-collection",
      icon: <Eye className="h-5 w-5 text-primary" />,
      title: t("privacy.collection.title"),
      content: t("privacy.collection.content"),
    },
    {
      id: "security",
      icon: <Lock className="h-5 w-5 text-primary" />,
      title: t("privacy.security.title"),
      content: t("privacy.security.content"),
    },
    {
      id: "storage",
      icon: <Server className="h-5 w-5 text-primary" />,
      title: t("privacy.storage.title"),
      content: t("privacy.storage.content"),
    },
    {
      id: "cookies",
      icon: <Cookie className="h-5 w-5 text-primary" />,
      title: t("privacy.cookies.title"),
      content: t("privacy.cookies.content"),
    },
    {
      id: "rights",
      icon: <HelpCircle className="h-5 w-5 text-primary" />,
      title: t("privacy.rights.title"),
      content: t("privacy.rights.content"),
    },
  ];

  return (
    <div className="w-full max-w-4xl space-y-8">
      <div className="space-y-4 text-center">
        <h1 className="text-4xl font-bold tracking-tight text-foreground">
          {t("privacy.title")}
        </h1>
        <p className="mx-auto max-w-2xl text-lg text-muted-foreground">
          {t("privacy.subtitle")}
        </p>
      </div>

      <Card className="w-full transition-shadow duration-300 hover:shadow-lg">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            {t("privacy.zeroKnowledge.title")}
          </CardTitle>
          <CardDescription>
            {t("privacy.zeroKnowledge.description")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-border bg-muted/50 p-4">
            <p className="text-sm leading-relaxed">
              {t("privacy.zeroKnowledge.details")}
            </p>
          </div>
        </CardContent>
      </Card>

      <ScrollArea className="h-full w-full rounded-md">
        <Accordion type="single" collapsible className="w-full space-y-4">
          {sections.map((section) => (
            <AccordionItem
              key={section.id}
              value={section.id}
              className="border-b-0 rounded-lg bg-card px-4 shadow-sm"
            >
              <AccordionTrigger className="py-4 hover:no-underline">
                <div className="flex items-center gap-3">
                  <div className="rounded-lg bg-primary/10 p-2">
                    {section.icon}
                  </div>
                  <span className="text-lg font-medium">{section.title}</span>
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-2 pb-4 pt-2 whitespace-pre-line text-muted-foreground leading-relaxed">
                {section.content}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </ScrollArea>

      <div className="space-y-2 pt-8 text-center text-sm text-muted-foreground">
        <p>{t("privacy.lastUpdated", { date: new Date().toLocaleDateString() })}</p>
        <p>{t("privacy.contact")}</p>
      </div>
    </div>
  );
}

const PrivacyPolicy = () => {
  const { t } = useTranslation();
  const showWebsiteChrome = shouldShowWebsiteChrome();

  return (
    <>
      <SEO
        title="Datenschutzerklaerung"
        description="Datenschutzerklaerung von Singra Vault. Erfahre, wie wir deine Daten schuetzen."
        path="/privacy"
        keywords={[
          "Datenschutz",
          "Datenschutzerklaerung",
          "Privacy Policy",
          "DSGVO",
          "clientseitige Verschlüsselung",
          "Datenverarbeitung",
        ]}
      />

      {showWebsiteChrome ? (
        <div className="min-h-screen bg-background flex flex-col">
          <Header />
          <main className="flex flex-1 flex-col items-center px-4 py-32 sm:px-6 lg:px-8">
            <PrivacyPolicyContent />
          </main>
          <Footer />
        </div>
      ) : (
        <DesktopSubpageFrame
          title={t("privacy.title")}
          description={t("privacy.subtitle")}
        >
          <PrivacyPolicyContent />
        </DesktopSubpageFrame>
      )}
    </>
  );
};

export default PrivacyPolicy;
