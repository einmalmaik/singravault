// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { FileText, Scale, ShieldCheck } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { createReturnState } from '@/services/returnNavigationState';

const LEGAL_RETURN_PATH = '/settings?tab=data-legal';

export function LegalLinksSettings() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const returnState = createReturnState(LEGAL_RETURN_PATH);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Scale className="h-5 w-5" />
          {t('settings.desktopLegal.title', 'Rechtliches & Informationen')}
        </CardTitle>
        <CardDescription>
          {t(
            'settings.desktopLegal.description',
            'Datenschutz, Impressum und Sicherheitsdokumentation bleiben auf jeder Plattform erreichbar.',
          )}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-3">
        <Button variant="outline" onClick={() => navigate('/privacy', { state: returnState })}>
          <FileText className="mr-2 h-4 w-4" />
          {t('landing.footer.privacy')}
        </Button>
        <Button variant="outline" onClick={() => navigate('/impressum', { state: returnState })}>
          <Scale className="mr-2 h-4 w-4" />
          {t('landing.footer.imprint')}
        </Button>
        <Button variant="outline" onClick={() => navigate('/security', { state: returnState })}>
          <ShieldCheck className="mr-2 h-4 w-4" />
          {t('landing.footer.securityWhitepaper')}
        </Button>
      </CardContent>
    </Card>
  );
}
