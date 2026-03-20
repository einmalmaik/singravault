// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Hero Section for Landing Page
 * 
 * Main call-to-action section with singra-core-ai style wordmark and animations.
 */

import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Shield, Lock, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SingraVaultLogo } from '@/components/SingraVaultLogo';
import { NebulaHeroBackground } from '@/components/NebulaHeroBackground';

export function Hero() {
  const { t } = useTranslation();

  return (
    <section className="relative overflow-hidden">
      {/* Canvas nebula background */}
      <NebulaHeroBackground variant="landing" showText={false} showParticles={false} />

      {/* Animated atmosphere overlay */}
      <div aria-hidden="true" className="singra-hero-atmosphere">
        <div className="singra-hero-light-beam" />
        <div className="singra-hero-vapor-sheet singra-hero-vapor-sheet-one" />
        <div className="singra-hero-vapor-sheet singra-hero-vapor-sheet-two" />
        <div className="singra-hero-vapor-sheet singra-hero-vapor-sheet-three" />
        <div className="singra-hero-fog singra-hero-fog-one" />
        <div className="singra-hero-fog singra-hero-fog-two" />
        <div className="singra-hero-fog singra-hero-fog-three" />
        <div className="singra-hero-fog singra-hero-fog-four" />
        <div className="singra-hero-fog singra-hero-fog-five" />
        <div className="singra-hero-fog singra-hero-fog-six" />

        {/* Vault emblem — abstract geometric shield/key, replaces text wordmark */}
        <div className="singra-hero-wordmark-stage" aria-hidden="true">
          <div className="singra-vault-emblem-stack">
            <svg
              className="singra-vault-emblem singra-vault-emblem-glow"
              viewBox="0 0 200 240"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M100 8 L188 44 L188 120 C188 168 148 204 100 224 C52 204 12 168 12 120 L12 44 Z" stroke="currentColor" strokeWidth="2" fill="none" />
              <circle cx="100" cy="110" r="32" stroke="currentColor" strokeWidth="2" fill="none" />
              <circle cx="100" cy="110" r="18" stroke="currentColor" strokeWidth="1.5" fill="none" />
              <line x1="100" y1="92" x2="100" y2="72" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="100" y1="128" x2="100" y2="148" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="68" y1="110" x2="48" y2="110" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="132" y1="110" x2="152" y2="110" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <circle cx="100" cy="110" r="5" fill="currentColor" />
            </svg>
            <svg
              className="singra-vault-emblem singra-vault-emblem-core"
              viewBox="0 0 200 240"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M100 8 L188 44 L188 120 C188 168 148 204 100 224 C52 204 12 168 12 120 L12 44 Z" stroke="currentColor" strokeWidth="2" fill="none" />
              <circle cx="100" cy="110" r="32" stroke="currentColor" strokeWidth="2" fill="none" />
              <circle cx="100" cy="110" r="18" stroke="currentColor" strokeWidth="1.5" fill="none" />
              <line x1="100" y1="92" x2="100" y2="72" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="100" y1="128" x2="100" y2="148" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="68" y1="110" x2="48" y2="110" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <line x1="132" y1="110" x2="152" y2="110" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
              <circle cx="100" cy="110" r="5" fill="currentColor" />
            </svg>
          </div>
        </div>
      </div>

      {/* Gradient overlay for text readability */}
      <div className="absolute inset-0 bg-[linear-gradient(90deg,hsl(228_26%_3%_/_0.96)_0%,hsl(228_26%_3%_/_0.84)_18%,hsl(228_26%_3%_/_0.38)_38%,transparent_62%),linear-gradient(180deg,transparent_0%,hsl(228_26%_3%_/_0.14)_66%,hsl(228_26%_3%_/_0.88)_100%)]" />
      <div className="absolute inset-y-0 right-0 hidden w-[62vw] bg-[radial-gradient(circle_at_84%_46%,hsl(var(--foreground)/0.1)_0%,transparent_46%)] blur-3xl lg:block" />

      <div className="container relative z-10 mx-auto px-4 pb-16 pt-28">
        <div className="flex min-h-[calc(100vh-7rem)] items-center">
          <div className="max-w-2xl space-y-8 text-center lg:text-left">
            {/* Security badge */}
            <div className="singra-hero-eyebrow inline-flex rounded-full border border-foreground/10 bg-background/10 px-4 py-1.5 text-[0.68rem] font-medium uppercase tracking-[0.34em] text-foreground/60 backdrop-blur-xl">
              <Shield className="mr-2 h-3.5 w-3.5" />
              AES-256 + Argon2id Encryption
            </div>

            {/* Main heading with singra-core-ai style */}
            <div className="space-y-5">
              <h1 className="singra-hero-title singra-headline-serif text-balance text-5xl font-bold tracking-[-0.055em] text-foreground [text-shadow:0_0_42px_hsl(228_26%_3%_/_0.96),0_0_110px_hsl(228_26%_3%_/_0.82)] md:text-7xl lg:text-[5.75rem] lg:leading-[0.92]">
                {t('landing.hero.title')}
                <br />
                <span className="text-gradient">Secure</span>
              </h1>
              <p className="singra-hero-subtitle max-w-2xl text-lg font-medium leading-relaxed text-foreground/90 [text-shadow:0_0_22px_hsl(228_26%_3%_/_0.9),0_0_68px_hsl(228_26%_3%_/_0.72)] md:text-2xl lg:text-[1.9rem] lg:leading-[1.3]">
                {t('landing.hero.subtitle')}
              </p>
            </div>

            {/* Description */}
            <p className="singra-hero-desc max-w-xl text-base leading-8 text-foreground/72 [text-shadow:0_0_20px_hsl(228_26%_3%_/_0.88)] md:text-lg">
              {t('landing.hero.description')}
            </p>

            {/* CTA Buttons with singra-core-ai style */}
            <div className="singra-hero-cta flex flex-col gap-5">
              <div className="flex flex-col items-center gap-4 sm:flex-row sm:justify-center lg:justify-start">
                <Link to="/auth">
                  <Button 
                    size="lg" 
                    className="min-h-[56px] min-w-[220px] rounded-full px-8 text-base shadow-[0_18px_60px_hsl(var(--primary)/0.18)] transition-all duration-300 hover:scale-[1.02] hover:shadow-[0_22px_72px_hsl(var(--primary)/0.24)]"
                  >
                    {t('landing.hero.cta')}
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                </Link>
                <a href="#security">
                  <Button
                    size="lg"
                    variant="outline"
                    className="min-h-[56px] min-w-[220px] rounded-full border-foreground/12 bg-background/10 px-8 text-base text-foreground/86 backdrop-blur-xl transition-all duration-300 hover:border-foreground/18 hover:bg-background/20"
                  >
                    <Lock className="mr-2 h-5 w-5" />
                    {t('landing.hero.ctaSecondary')}
                  </Button>
                </a>
              </div>
            </div>

            {/* Trust indicators */}
            <div className="grid gap-3 pt-4 sm:grid-cols-3">
              {[
                { label: 'Zero-Knowledge', value: '100%' },
                { label: 'Open Source', value: 'Public' },
                { label: 'End-to-End', value: 'Encrypted' },
              ].map((stat, index) => (
                <div
                  key={stat.label}
                  className="singra-hero-pill rounded-[24px] border border-foreground/10 bg-background/10 px-5 py-4 text-center backdrop-blur-xl lg:text-left"
                  style={{ animationDelay: `${850 + index * 140}ms` }}
                >
                  <div className="text-2xl font-semibold tracking-[-0.04em] text-primary md:text-3xl">{stat.value}</div>
                  <div className="mt-2 text-[0.7rem] uppercase tracking-[0.28em] text-foreground/45">{stat.label}</div>
                </div>
              ))}
            </div>

            {/* Logo section */}
            <div className="flex items-center justify-center gap-3 pt-8 lg:justify-start">
              <SingraVaultLogo size={32} />
              <div className="flex flex-col leading-none">
                <span className="text-sm font-semibold tracking-tight text-foreground/80">SingraVault</span>
                <span className="text-[0.6rem] uppercase tracking-[0.2em] text-foreground/40">Password Manager</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-b from-transparent to-[hsl(228,26%,3%)]" />
    </section>
  );
}
