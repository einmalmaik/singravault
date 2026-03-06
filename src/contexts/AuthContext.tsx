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

const SESSION_FALLBACK_STORAGE_KEY = 'singra-auth-session-fallback';

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

function persistSessionFallback(session: Session | null): void {
    if (typeof window === 'undefined') {
        return;
    }

    if (!session?.access_token || !session?.refresh_token) {
        window.sessionStorage.removeItem(SESSION_FALLBACK_STORAGE_KEY);
        return;
    }

    window.sessionStorage.setItem(SESSION_FALLBACK_STORAGE_KEY, JSON.stringify({
        access_token: session.access_token,
        refresh_token: session.refresh_token,
    }));
}

function clearSessionFallback(): void {
    if (typeof window === 'undefined') {
        return;
    }

    window.sessionStorage.removeItem(SESSION_FALLBACK_STORAGE_KEY);
}

function readSessionFallback(): { access_token: string; refresh_token: string } | null {
    if (typeof window === 'undefined') {
        return null;
    }

    const raw = window.sessionStorage.getItem(SESSION_FALLBACK_STORAGE_KEY);
    if (!raw) {
        return null;
    }

    try {
        const parsed = JSON.parse(raw) as Partial<Session>;
        if (
            typeof parsed.access_token !== 'string'
            || typeof parsed.refresh_token !== 'string'
            || !parsed.access_token
            || !parsed.refresh_token
        ) {
            clearSessionFallback();
            return null;
        }

        return {
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
        };
    } catch {
        clearSessionFallback();
        return null;
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
    const restoreSessionFromFallback = async (): Promise<boolean> => {
      const storedSession = readSessionFallback();
      if (!storedSession) {
        return false;
      }

      const { data, error } = await supabase.auth.setSession(storedSession);
      if (error || !data.session) {
        clearSessionFallback();
        return false;
      }

      return true;
    };

    // 1. Initialer Auth-Status aus Memory
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, currentSession) => {
        console.debug(`[AuthContext] Memory auth state changed: ${event}`);
        setSession(currentSession);
        setUser(currentSession?.user ?? null);

        if (currentSession?.access_token && currentSession?.refresh_token) {
          persistSessionFallback(currentSession);
        } else if (event === 'SIGNED_OUT') {
          clearSessionFallback();
        }

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
        await restoreSessionFromFallback();
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
          } else {
            await restoreSessionFromFallback();
          }
        } else {
          await restoreSessionFromFallback();
        }
      } catch (err) {
        console.warn('[AuthContext] No active session found from BFF.');
        await restoreSessionFromFallback();
      } finally {
        setLoading(false);
        setAuthReady(true);
      }
    };

    hydrateSession();

    return () => subscription.unsubscribe();
  }, []);

  const signOut = async () => {
    clearSessionFallback();
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

