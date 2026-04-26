// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Hero Section for Landing Page
 *
 * Main call-to-action section with full-section brand artwork.
 */

import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Shield, Lock, ArrowRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { BrandMedia } from '@/components/BrandMedia';
import { SingraVaultLogo } from '@/components/SingraVaultLogo';

const LANDING_HERO_VIDEO_SOURCES = [
  { src: '/brand/landingpage.webm', type: 'video/webm' },
  { src: '/brand/landingpage.mp4', type: 'video/mp4' },
];

export function Hero() {
  const { t } = useTranslation();

  return (
    <section className="relative overflow-hidden">
      <div className="absolute inset-0 bg-[hsl(228_26%_3%)]" />

      <BrandMedia
        alt=""
        fallbackImageSrc="/brand/landingpage.png"
        animatedImageSrc="/brand/landingpage.gif"
        videoSources={LANDING_HERO_VIDEO_SOURCES}
        width={1800}
        height={874}
        frameClassName="singra-hero-artwork"
        mediaClassName="singra-hero-artwork-image"
      />

      {/* Gradient overlay for text readability */}
      <div className="absolute inset-0 bg-[linear-gradient(90deg,hsl(228_26%_3%_/_0.96)_0%,hsl(228_26%_3%_/_0.88)_20%,hsl(228_26%_3%_/_0.48)_43%,transparent_72%),linear-gradient(180deg,hsl(228_26%_3%_/_0.08)_0%,transparent_34%,hsl(228_26%_3%_/_0.24)_70%,hsl(228_26%_3%_/_0.92)_100%)]" />
      <div className="absolute inset-y-0 right-0 hidden w-[62vw] bg-[radial-gradient(circle_at_84%_46%,hsl(var(--foreground)/0.1)_0%,transparent_46%)] blur-3xl lg:block" />

      <div className="container relative z-10 mx-auto px-4 pb-16 pt-28">
        <div className="flex min-h-[calc(100vh-7rem)] items-center">
          <div className="max-w-2xl space-y-8 text-center lg:text-left">
            {/* Security badge */}
            <div className="singra-hero-eyebrow inline-flex rounded-full border border-foreground/10 bg-background/10 px-4 py-1.5 text-[0.68rem] font-medium uppercase tracking-[0.34em] text-foreground/60 backdrop-blur-xl">
              <Shield className="mr-2 h-3.5 w-3.5" />
              AES-256 + Argon2id Encryption
            </div>

            {/* Main heading */}
            <div className="space-y-5">
              <h1 className="singra-hero-title singra-headline-serif text-balance text-5xl font-bold tracking-[-0.055em] text-foreground [text-shadow:0_0_42px_hsl(228_26%_3%_/_0.96),0_0_110px_hsl(228_26%_3%_/_0.82)] md:text-7xl lg:text-[5.75rem] lg:leading-[0.92]">
                {t('landing.hero.title')}
                <br />
                <span className="text-gradient">{t('landing.hero.titleHighlight')}</span>
              </h1>
              <p className="singra-hero-subtitle max-w-2xl text-lg font-medium leading-relaxed text-foreground/90 [text-shadow:0_0_22px_hsl(228_26%_3%_/_0.9),0_0_68px_hsl(228_26%_3%_/_0.72)] md:text-2xl lg:text-[1.9rem] lg:leading-[1.3]">
                {t('landing.hero.subtitle')}
              </p>
            </div>

            {/* Description */}
            <p className="singra-hero-desc max-w-xl text-base leading-8 text-foreground/72 [text-shadow:0_0_20px_hsl(228_26%_3%_/_0.88)] md:text-lg">
              {t('landing.hero.description')}
            </p>

            {/* CTA Buttons */}
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
