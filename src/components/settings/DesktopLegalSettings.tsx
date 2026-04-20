// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";
import { FileText, Scale, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function DesktopLegalSettings() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Scale className="w-5 h-5" />
          {t("settings.desktopLegal.title", "Rechtliches & Informationen")}
        </CardTitle>
        <CardDescription>
          {t("settings.desktopLegal.description", "Datenschutz, Impressum und Sicherheitsdokumentation direkt in der App.")}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-3">
        <Button variant="outline" onClick={() => navigate("/privacy")}>
          <FileText className="w-4 h-4 mr-2" />
          {t("landing.footer.privacy")}
        </Button>
        <Button variant="outline" onClick={() => navigate("/impressum")}>
          <Scale className="w-4 h-4 mr-2" />
          {t("landing.footer.imprint")}
        </Button>
        <Button variant="outline" onClick={() => navigate("/security")}>
          <ShieldCheck className="w-4 h-4 mr-2" />
          {t("landing.footer.securityWhitepaper")}
        </Button>
      </CardContent>
    </Card>
  );
}
