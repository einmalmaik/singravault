// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Index Page
 * 
 * Redirects to Landing page for the root route.
 */

import Landing from './Landing';
import { isTauriRuntime } from '@/platform/runtime';
import { Navigate, useSearchParams } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';

export default function Index() {
  const [searchParams] = useSearchParams();
  const [isBouncing, setIsBouncing] = useState(false);

  useEffect(() => {
    // If we are on web and see a login token with source=tauri, bounce back to the app.
    // This handles cases where Supabase redirects to the root instead of /auth.
    const isWeb = !isTauriRuntime();
    const hasTauriSource = searchParams.get('source') === 'tauri' || searchParams.get('redirect')?.includes('source=tauri');
    const hasTokens = window.location.hash.includes('access_token=') || window.location.search.includes('access_token=');

    if (isWeb && hasTauriSource && hasTokens) {
      setIsBouncing(true);
      const appUrl = `singravault://auth/callback${window.location.search}${window.location.hash}`;
      
      setTimeout(() => {
        window.location.assign(appUrl);
      }, 1000);
    }
  }, [searchParams]);

  if (isTauriRuntime()) {
    return <Navigate to="/auth" replace />;
  }

  if (isBouncing) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background text-center p-6">
        <div className="space-y-6 max-w-xs animate-in fade-in duration-500">
          <div className="relative mx-auto w-16 h-16">
            <div className="absolute inset-0 rounded-full bg-primary/20 animate-ping" />
            <img src="/singra-icon.png" alt="" className="relative w-16 h-16 rounded-full shadow-2xl" />
          </div>
          <div className="space-y-2">
            <h2 className="text-xl font-bold tracking-tight">Anmeldung erkannt</h2>
            <p className="text-sm text-muted-foreground">
              Wir leiten dich zurück zur Singra Vault Desktop-App weiter...
            </p>
          </div>
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary/60" />
        </div>
      </div>
    );
  }
  
  return <Landing />;
}
