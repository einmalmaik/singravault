// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { runtimeConfig } from "@/config/runtimeConfig";

export function AppConfigurationNotice() {
  if (runtimeConfig.isSupabaseConfigured) {
    return null;
  }

  return (
    <div className="fixed inset-x-4 top-4 z-50 mx-auto max-w-3xl rounded-lg border border-destructive/35 bg-destructive/15 px-4 py-3 text-sm text-foreground shadow-lg backdrop-blur-xl">
      Supabase-Konfiguration fehlt. Anmeldung, Synchronisierung und Premium-Dienste sind lokal deaktiviert.
    </div>
  );
}

