// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authentication Context for Singra Vault
 * 
 * Basiert nun auf einem BFF Pattern: JWTs werden NICHT im localStorage persistiert,
 * sondern über HttpOnly Cookies und kurzlebige In-Memory Tokens verwaltet.
 */

import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';

// ============ Iframe Detection ============

/**
 * Erkennt ob die App in einem Iframe läuft (z.B. Lovable Preview).
 * In Iframes werden Third-Party Cookies blockiert, daher nutzen wir
 * einen Cookie-freien Fallback.
 */
function isInIframe(): boolean {
    try {
        return window.self !== window.top;
    } catch {
        return true; // Cross-origin iframe → blocked access = iframe
    }
}

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  authReady: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [authReady, setAuthReady] = useState(false);

  useEffect(() => {
    // 1. Initialer Auth-Status aus Memory
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, currentSession) => {
        console.debug(`[AuthContext] Memory auth state changed: ${event}`);
        setSession(currentSession);
        setUser(currentSession?.user ?? null);

        if (event !== 'INITIAL_SESSION') {
          setLoading(false);
          setAuthReady(true);
        }
      }
    );

    // 2. Session-Hydration: BFF Cookie (Standalone) oder Skip (Iframe)
    const hydrateSession = async () => {
      // Im Iframe können Third-Party Cookies nicht gesetzt/gelesen werden.
      // Daher überspringen wir den Cookie-basierten Session-Fetch komplett.
      if (isInIframe()) {
        console.debug('[AuthContext] Running in iframe – skipping BFF cookie hydration.');
        setLoading(false);
        setAuthReady(true);
        return;
      }

      try {
        const API_URL = import.meta.env.VITE_SUPABASE_URL + '/functions/v1';
        const res = await fetch(`${API_URL}/auth-session`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`
          },
          credentials: 'include'
        });

        if (res.ok) {
          const { session: bffSession } = await res.json();
          if (bffSession && bffSession.access_token) {
            await supabase.auth.setSession({
              access_token: bffSession.access_token,
              refresh_token: bffSession.refresh_token || '',
            });
          }
        }
      } catch (err) {
        console.warn('[AuthContext] No active session found from BFF.');
      } finally {
        setLoading(false);
        setAuthReady(true);
      }
    };

    hydrateSession();

    return () => subscription.unsubscribe();
  }, []);

  const signOut = async () => {
    // 1. Supabase Memory-Session löschen
    const { error: signOutError } = await supabase.auth.signOut();
    if (signOutError) {
      console.error('[AuthContext] Failed to terminate GoTrue session:', signOutError);
      throw signOutError;
    }

    // 2. Cookie im Backend killen (nur wenn nicht im Iframe)
    if (!isInIframe()) {
      const API_URL = import.meta.env.VITE_SUPABASE_URL + '/functions/v1';
      const res = await fetch(`${API_URL}/auth-session`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY}`
        },
        credentials: 'include'
      });

      if (!res.ok) {
        console.error('[AuthContext] Failed to invalidate BFF session, status:', res.status);
      }
    }
  };

  return (
    <AuthContext.Provider value={{ user, session, loading, authReady, signOut }}>
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

