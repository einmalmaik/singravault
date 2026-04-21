// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Landing Page
 * 
 * Public landing page showcasing Singra Vault features.
 */

import { Header } from '@/components/landing/Header';
import { Hero } from '@/components/landing/Hero';
import { SecurityFeatures } from '@/components/landing/SecurityFeatures';
import { Features } from '@/components/landing/Features';
import { PWASection } from '@/components/landing/PWASection';
import { OpenSource } from '@/components/landing/OpenSource';
import { Comparison } from '@/components/landing/Comparison';
import { Footer } from '@/components/landing/Footer';
import { SEO, createWebsiteStructuredData, createSoftwareAppStructuredData } from '@/components/SEO';
import { FadeInSection } from '@/components/FadeInSection';
import { getExtension } from '@/extensions/registry';

export default function Landing() {
  const structuredData = {
    ...createWebsiteStructuredData(),
    ...createSoftwareAppStructuredData(),
  };
  const AfterHeroSlot = getExtension('landing.after-hero');

  return (
    <div className="min-h-screen flex flex-col">
      <SEO
        title="Sicherer Zero-Knowledge Passwort-Manager"
        description="Singra Vault ist ein sicherer Zero-Knowledge Passwort Manager mit clientseitiger Verschlüsselung. Kostenlos, Open Source, und mit voller Kontrolle über deine Daten."
        path="/"
        keywords={[
          'Passwort Manager kostenlos',
          'Passwortmanager Open Source',
          'Zero-Knowledge Encryption',
          'Sichere Passwörter',
          'Passwort Generator',
          'Zwei-Faktor-Authentifizierung',
          '2FA',
          'AES-256 Verschlüsselung',
        ]}
        structuredData={structuredData}
      />
      <Header />
      <main className="flex-1">
        <Hero />
        {AfterHeroSlot && <FadeInSection delay={50}><AfterHeroSlot /></FadeInSection>}
        <FadeInSection><SecurityFeatures /></FadeInSection>
        <FadeInSection delay={100}><Features /></FadeInSection>
        <FadeInSection delay={200}><PWASection /></FadeInSection>
        <FadeInSection delay={300}><OpenSource /></FadeInSection>
        <FadeInSection delay={400}><Comparison /></FadeInSection>
      </main>
      <Footer />
    </div>
  );
}
