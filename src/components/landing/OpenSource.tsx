// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Open Source Section
 * 
 * Highlights the open-source nature of Singra Vault.
 */

import { useTranslation } from 'react-i18next';
import { Github, Users, ExternalLink } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function OpenSource() {
  const { t } = useTranslation();

  return (
    <section className="py-20 bg-primary/5">
      <div className="container px-4">
        <div className="max-w-4xl mx-auto">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            {/* Content */}
            <div>
              <div className="inline-flex items-center gap-2 px-3 py-1 mb-4 text-sm font-medium rounded-full bg-primary/10 text-primary">
                <Github className="w-4 h-4" />
                <span>BSL 1.1 · Source Available</span>
              </div>

              <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
                {t('landing.openSource.title')}
              </h2>

              <p className="text-lg text-muted-foreground mb-2">
                {t('landing.openSource.subtitle')}
              </p>

              <p className="text-muted-foreground mb-8">
                {t('landing.openSource.description')}
              </p>

              <div className="flex flex-col sm:flex-row gap-3 flex-wrap">
                <Button asChild className="gap-2">
                  <a href="https://github.com/einmalmaik/zingra-secure-vault" target="_blank" rel="noopener noreferrer">
                    <Github className="w-4 h-4" />
                    {t('landing.openSource.cta')}
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </Button>
                <Button asChild variant="outline" className="gap-2">
                  <a href="https://github.com/einmalmaik/zingra-secure-vault/discussions" target="_blank" rel="noopener noreferrer">
                    <Users className="w-4 h-4" />
                    {t('landing.openSource.community')}
                  </a>
                </Button>
              </div>
            </div>

            {/* Visual */}
            <div className="relative">
              <div className="aspect-square rounded-2xl bg-gradient-to-br from-primary/20 to-primary/5 border flex items-center justify-center">
                <div className="text-center p-8">
                  {/* Code preview mockup */}
                  <div className="bg-card rounded-lg p-4 shadow-lg text-left font-mono text-sm">
                    <div className="flex gap-2 mb-3">
                      <div className="w-3 h-3 rounded-full bg-destructive" />
                      <div className="w-3 h-3 rounded-full bg-warning" />
                      <div className="w-3 h-3 rounded-full bg-success" />
                    </div>
                    <code className="text-xs sm:text-sm">
                      <span className="text-muted-foreground">// Zero-Knowledge Encryption</span>
                      <br />
                      <span className="text-primary">const</span> key = <span className="text-success">deriveKey</span>(
                      <br />
                      &nbsp;&nbsp;masterPassword,
                      <br />
                      &nbsp;&nbsp;salt,
                      <br />
                      &nbsp;&nbsp;<span className="text-warning">'argon2id'</span>
                      <br />
                      );
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
