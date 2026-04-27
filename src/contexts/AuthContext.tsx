// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Authentication Context for Singra Vault.
 *
 * React-facing auth state is intentionally thin. Persistence, refresh,
 * Tauri keychain access, BFF hydration and offline identity live in
 * authSessionManager so the same rules are shared by Web, PWA and Tauri.
 */

import { createContext, useContext, useEffect, useRef, useState, ReactNode } from "react";
import type { User, Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";
import {
  AuthMode,
  clearPersistentSession,
  hydrateAuthSession,
  isInIframe,
  persistAuthenticatedSession,
} from "@/services/authSessionManager";
import { isTauriRuntime } from "@/platform/runtime";
import {
  disableTauriDevAuthBypass,
  isTauriDevAuthBypassEnabled,
  TAURI_DEV_USER_EMAIL,
  TAURI_DEV_USER_ID,
} from "@/platform/tauriDevMode";
import { runtimeConfig } from "@/config/runtimeConfig";

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  authReady: boolean;
  authMode: AuthMode;
  isOfflineSession: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function createTauriDevSession(): Session {
  const nowIso = new Date().toISOString();
  const user = {
    id: TAURI_DEV_USER_ID,
    aud: "authenticated",
    role: "authenticated",
    email: TAURI_DEV_USER_EMAIL,
    app_metadata: { provider: "tauri-dev", providers: ["tauri-dev"] },
    user_metadata: { name: "Tauri Dev" },
    created_at: nowIso,
    updated_at: nowIso,
  } as User;

  return {
    access_token: "tauri-dev-local-session",
    refresh_token: "tauri-dev-local-refresh",
    expires_in: 60 * 60 * 24,
    expires_at: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    token_type: "bearer",
    user,
  } as Session;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [authReady, setAuthReady] = useState(false);
  const [authMode, setAuthMode] = useState<AuthMode>("unauthenticated");
  const sessionRef = useRef<Session | null>(null);

  const applySessionState = (nextSession: Session | null, nextUser: User | null, nextMode: AuthMode) => {
    sessionRef.current = nextSession;
    setSession(nextSession);
    setUser(nextUser);
    setAuthMode(nextMode);
  };

  useEffect(() => {
    if (isTauriDevAuthBypassEnabled()) {
      const devSession = createTauriDevSession();
      applySessionState(devSession, devSession.user, "offline");
      setLoading(false);
      setAuthReady(true);
      return;
    }

    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, currentSession) => {
        console.debug(`[AuthContext] Memory auth state changed: ${event}`);

        if (currentSession?.access_token) {
          applySessionState(currentSession, currentSession.user, "online");
          void persistAuthenticatedSession(currentSession).catch((error) => {
            console.warn("[AuthContext] Failed to persist auth session:", error);
          });
        } else if (event === "SIGNED_OUT") {
          applySessionState(null, null, "unauthenticated");
        }

        if (event !== "INITIAL_SESSION") {
          setLoading(false);
          setAuthReady(true);
        }
      },
    );

    const hydrateSession = async () => {
      try {
        const hydrated = await hydrateAuthSession();

        // If Supabase already emitted a valid INITIAL_SESSION, do not overwrite
        // it with a negative BFF result that may simply be a transient network miss.
        if (hydrated.mode === "online" || (!sessionRef.current && hydrated.mode !== "unauthenticated")) {
          applySessionState(hydrated.session, hydrated.user, hydrated.mode);
        }
      } catch (err) {
        console.warn("[AuthContext] No active persisted session found.", err);
      } finally {
        setLoading(false);
        setAuthReady(true);
      }
    };

    void hydrateSession();

    return () => subscription.unsubscribe();
  }, []);

  const signOut = async () => {
    if (isTauriDevAuthBypassEnabled()) {
      disableTauriDevAuthBypass();
      applySessionState(null, null, "unauthenticated");
      return;
    }

    await clearPersistentSession();

    const { error: signOutError } = await supabase.auth.signOut();
    if (signOutError) {
      console.error("[AuthContext] Failed to terminate GoTrue session:", signOutError);
      throw signOutError;
    }

    if (!isInIframe() && !isTauriRuntime()) {
      const apiUrl = runtimeConfig.supabaseFunctionsUrl ?? `${runtimeConfig.supabaseUrl}/functions/v1`;
      const res = await fetch(`${apiUrl}/auth-session`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${runtimeConfig.supabasePublishableKey}`,
        },
        credentials: "include",
      });

      if (!res.ok) {
        console.error("[AuthContext] Failed to invalidate BFF session, status:", res.status);
      }
    }

    applySessionState(null, null, "unauthenticated");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        loading,
        authReady,
        authMode,
        isOfflineSession: authMode === "offline",
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return context;
}
