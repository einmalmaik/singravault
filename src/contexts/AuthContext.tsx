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
      (event, session) => {
        console.debug(`[AuthContext] Memory auth state changed: ${event}`);
        setSession(session);
        setUser(session?.user ?? null);

        if (event !== 'INITIAL_SESSION') {
          setLoading(false);
          setAuthReady(true);
        }
      }
    );

    // 2. Rufe das BFF-Backend auf, um ein kurzes Session-Token aus dem HttpOnly Cookie zu laden.
    // Da wir in dieser reinen SPA-Architektur nur Edge Functions haben, muss das Frontend
    // hier die Edge Function /session-token aufrufen... 
    // Wir mocken diesen Aufruf für den Prototyp hier, da der Fokus auf dem Code-Structure liegt.
    const fetchSessionFromHttpOnlyCookie = async () => {
      try {
        const API_URL = import.meta.env.VITE_SUPABASE_URL + '/functions/v1';
        const res = await fetch(`${API_URL}/auth-session`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
          },
          credentials: 'include'
        });

        if (res.ok) {
          const { session } = await res.json();
          if (session && session.access_token) {
            await supabase.auth.setSession({
              access_token: session.access_token,
              refresh_token: session.refresh_token || '',
            });
          }
        }
      } catch (err) {
        console.warn('No active session found from BFF.');
      } finally {
        setLoading(false);
        setAuthReady(true);
      }
    };

    fetchSessionFromHttpOnlyCookie();

    return () => subscription.unsubscribe();
  }, []);

  const signOut = async () => {
    // 1. Supabase Memory-Session löschen
    await supabase.auth.signOut();

    // 2. Cookie im Backend killen (BFF Logout Endpoint aufrufen)
    // Wir löschen den Cookie Client Seitig (da wir keinen /auth-logout Endpunkt haben gerade)
    document.cookie = "sb-bff-session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
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

