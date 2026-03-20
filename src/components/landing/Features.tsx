// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Features Section
 * 
 * Displays all main features of Singra Vault.
 */

import { useTranslation } from 'react-i18next';
import { KeyRound, Wand2, Smartphone, FileText, FolderOpen, MonitorSmartphone } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';

const features = [
  { key: 'passwordManager', icon: KeyRound },
  { key: 'generator', icon: Wand2 },
  { key: 'totp', icon: Smartphone },
  { key: 'secureNotes', icon: FileText },
  { key: 'categories', icon: FolderOpen },
  { key: 'crossPlatform', icon: MonitorSmartphone },
];

export function Features() {
  const { t } = useTranslation();

  return (
    <section id="features" className="py-20">
      <div className="container px-4">
        <div className="text-center mb-16">
          <h2 className="singra-headline-serif text-3xl sm:text-4xl font-bold mb-4">
            {t('landing.features.title')}
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            {t('landing.features.subtitle')}
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {features.map((feature, index) => (
            <Card
              key={feature.key}
              className="group hover:shadow-md hover:border-primary/20 transition-all duration-300 animate-fade-in"
              style={{ animationDelay: `${index * 0.05}s` }}
            >
              <CardContent className="p-6 flex gap-4">
                {/* Icon */}
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                  <feature.icon className="w-5 h-5" />
                </div>

                {/* Content */}
                <div>
                  <h3 className="font-semibold mb-1">
                    {t(`landing.features.${feature.key}.title`)}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {t(`landing.features.${feature.key}.description`)}
                  </p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
