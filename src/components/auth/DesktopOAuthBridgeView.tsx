// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, Copy, ExternalLink, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { SEO } from "@/components/SEO";
import { createTauriOAuthCallbackUrl, parseOAuthCallbackPayload } from "@/platform/tauriOAuthCallback";

export function DesktopOAuthBridgeView() {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const autoOpenTriggeredRef = useRef(false);

  const callbackPayload = useMemo(() => {
    if (typeof window === "undefined") {
      return null;
    }

    return parseOAuthCallbackPayload(window.location.href, window.location.origin);
  }, []);

  const appLink = useMemo(() => {
    if (!callbackPayload?.hasAuthPayload) {
      return null;
    }

    return createTauriOAuthCallbackUrl(callbackPayload.params);
  }, [callbackPayload]);

  useEffect(() => {
    if (!appLink || autoOpenTriggeredRef.current || typeof window === "undefined") {
      return;
    }

    autoOpenTriggeredRef.current = true;
    window.setTimeout(() => {
      window.location.assign(appLink);
    }, 120);
  }, [appLink]);

  const copyRawLink = async () => {
    if (!appLink || !navigator.clipboard?.writeText) {
      return;
    }

    await navigator.clipboard.writeText(appLink);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  const errorMessage = callbackPayload?.error?.description
    ?? callbackPayload?.error?.error
    ?? null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-6 py-10">
      <SEO title="Desktop-App verbinden" description="Singra Vault Desktop-App verbinden." noIndex={true} />
      <div className="w-full max-w-lg rounded-lg border border-border/60 bg-card/95 p-8 shadow-xl shadow-black/10">
        <div className="flex items-center gap-3 mb-6">
          <img
            src="/brand/auth-panel.png"
            alt="Singra Vault"
            className="h-12 w-12 rounded-xl object-cover shadow-lg shadow-primary/20 ring-1 ring-border/70"
          />
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Verbindung mit Singra Vault</h1>
            <p className="text-sm text-muted-foreground">
              Browser und Desktop-App werden jetzt verbunden.
            </p>
          </div>
        </div>

        {appLink ? (
          <div className="space-y-5">
            <div className="flex items-center gap-3 rounded-md border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              <span>
                Die Desktop-App wird geöffnet. Falls dein Browser nachfragt, bestätige <strong>App öffnen</strong>.
              </span>
            </div>

            <div className="flex flex-wrap gap-3">
              <Button asChild>
                <a href={appLink}>
                  <ExternalLink className="w-4 h-4 mr-2" />
                  App öffnen
                </a>
              </Button>
              <Button variant="outline" type="button" onClick={() => void copyRawLink()}>
                {copied ? <Check className="w-4 h-4 mr-2" /> : <Copy className="w-4 h-4 mr-2" />}
                Rohlink kopieren
              </Button>
            </div>

            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Falls die automatische Übergabe nicht greift, füge diesen Link in der Desktop-App manuell ein.
              </p>
              <div className="break-all rounded-md border border-border bg-muted/30 px-3 py-2 text-xs text-foreground">
                {appLink}
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-md border border-destructive/20 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            {errorMessage ?? t("auth.errors.generic")}
          </div>
        )}
      </div>
    </div>
  );
}
