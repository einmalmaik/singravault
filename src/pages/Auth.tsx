// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authentication Page
 * 
 * Handles login, passkey, and signup flows via Custom Edge Functions (BFF Pattern).
 */

import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import type { Session } from '@supabase/supabase-js';
import { Mail, Lock, Eye, EyeOff, Loader2 } from 'lucide-react';
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { NebulaHeroBackground } from '@/components/NebulaHeroBackground';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { TwoFactorVerificationModal } from '@/components/auth/TwoFactorVerificationModal';
import { supabase } from '@/integrations/supabase/client';
import { SEO } from '@/components/SEO';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import { resolvePostAuthRedirectPath } from '@/services/postAuthRedirectService';
import { applyAuthenticatedSession } from '@/services/authSessionManager';
import { getInitialDeepLinks, listenForDeepLinks } from '@/platform/deepLink';
import { getOAuthRedirectUrl } from '@/platform/oauthRedirect';
import { isTauriRuntime } from '@/platform/runtime';
import { runtimeConfig } from '@/config/runtimeConfig';
import * as opaqueClient from '@/services/opaqueService';

const loginSchema = z.object({
  email: z.string().email('auth.errors.invalidEmail'),
  password: z.string().min(1, 'auth.errors.invalidCredentials'),
});

const signupSchema = z.object({
  email: z.string().email('auth.errors.invalidEmail'),
  // NIST 800-63B Mindestlänge von 12 Zeichen
  password: z.string().min(12, 'Passwort muss mindestens 12 Zeichen haben.'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'auth.errors.passwordMismatch',
  path: ['confirmPassword'],
});

const recoverSchema = z.object({
  email: z.string().email('auth.errors.invalidEmail'),
});

const updatePasswordSchema = z.object({
  password: z.string().min(12, 'Passwort muss mindestens 12 Zeichen haben.'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'auth.errors.passwordMismatch',
  path: ['confirmPassword'],
});

type LoginFormData = z.infer<typeof loginSchema>;
type SignupFormData = z.infer<typeof signupSchema>;
type RecoverFormData = z.infer<typeof recoverSchema>;
type UpdatePasswordFormData = z.infer<typeof updatePasswordSchema>;

export default function Auth() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();
  const { user, authReady } = useAuth();

  const urlToken = searchParams.get('token') || (window.location.hash.includes('type=recovery') ? 'supabase-recovery' : null);
  const [mode, setMode] = useState<'login' | 'signup' | 'verify_signup' | 'recover' | 'verify_recover' | 'update_password'>(
    urlToken ? 'update_password' :
      searchParams.get('mode') === 'signup' ? 'signup' :
        searchParams.get('mode') === 'recover' ? 'recover' : 'login'
  );
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const postAuthRedirectPath = resolvePostAuthRedirectPath(searchParams.get('redirect'), location.state);
  const API_URL = runtimeConfig.supabaseFunctionsUrl ?? `${runtimeConfig.supabaseUrl}/functions/v1`;
  const inIframe = (() => {
    try { return window.self !== window.top; } catch { return true; }
  })();
  const usesCookieSession = !inIframe && !isTauriRuntime();

  useEffect(() => {
    let cancelled = false;
    let unlisten: (() => void) | null = null;

    const extractCallbackTokens = (callbackUrl: string) => {
      try {
        const parsed = new URL(callbackUrl, window.location.origin);
        const hashParams = new URLSearchParams(parsed.hash.startsWith('#') ? parsed.hash.slice(1) : '');
        const searchParams = parsed.searchParams;
        const accessToken = hashParams.get('access_token') ?? searchParams.get('access_token');
        const refreshToken = hashParams.get('refresh_token') ?? searchParams.get('refresh_token');

        if (!accessToken || !refreshToken) {
          return null;
        }

        return { access_token: accessToken, refresh_token: refreshToken };
      } catch {
        return null;
      }
    };

    const applyCallbackSession = async (callbackUrl: string) => {
      const tokens = extractCallbackTokens(callbackUrl);
      if (!tokens || cancelled) {
        return;
      }

      try {
        await applyAuthenticatedSession(tokens);

        if (usesCookieSession) {
          const syncResponse = await fetch(`${API_URL}/auth-session`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${tokens.access_token}`,
            },
            credentials: 'include',
            body: JSON.stringify({
              action: 'oauth-sync',
              refreshToken: tokens.refresh_token,
            }),
          });

          if (!syncResponse.ok) {
            console.warn('[Auth] OAuth session cookie sync failed:', syncResponse.status);
          } else {
            const syncPayload = await syncResponse.json().catch(() => null) as {
              session?: Session;
            } | null;
            const syncedSession = syncPayload?.session;

            if (syncedSession?.access_token && syncedSession?.refresh_token) {
              await applyAuthenticatedSession({
                access_token: syncedSession.access_token,
                refresh_token: syncedSession.refresh_token,
              });
            }
          }
        }
      } catch (err) {
        console.error('[Auth] Failed to apply callback session from URL hash:', err);
      } finally {
        if (window.location.hash.includes('access_token=')) {
          const cleanUrl = `${window.location.pathname}${window.location.search}`;
          window.history.replaceState({}, document.title, cleanUrl);
        }
      }
    };

    void applyCallbackSession(window.location.href);
    void getInitialDeepLinks().then((urls) => {
      urls.forEach((url) => void applyCallbackSession(url));
    });
    void listenForDeepLinks((urls) => {
      urls.forEach((url) => void applyCallbackSession(url));
    }).then((cleanup) => {
      unlisten = cleanup;
    });

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [API_URL, usesCookieSession]);

  useEffect(() => {
    if (!authReady) {
      return;
    }

    if (user && mode !== 'update_password') {
      navigate(postAuthRedirectPath, { replace: true });
    }
  }, [authReady, user, mode, navigate, postAuthRedirectPath]);

  // Note: 2FA Logik (TOTP) bleibt bestehen, wird hier vereinfacht
  const [show2FAModal, setShow2FAModal] = useState(false);
  const [pendingLoginData, setPendingLoginData] = useState<LoginFormData | null>(null);

  const passwordCheck = usePasswordCheck({ enforceStrong: true });

  const loginForm = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  const signupForm = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: { email: '', password: '', confirmPassword: '' },
  });

  const verifySignupSchema = z.object({
    code: z.string().length(8, 'Der Code muss 8 Zeichen lang sein.'),
  });

  type VerifySignupFormData = z.infer<typeof verifySignupSchema>;

  const verifySignupForm = useForm<VerifySignupFormData>({
    resolver: zodResolver(verifySignupSchema),
    defaultValues: { code: '' },
  });

  const verifyRecoverSchema = z.object({
    code: z.string().length(8, 'Der Code muss 8 Zeichen lang sein.'),
  });

  type VerifyRecoverFormData = z.infer<typeof verifyRecoverSchema>;

  const verifyRecoverForm = useForm<VerifyRecoverFormData>({
    resolver: zodResolver(verifyRecoverSchema),
    defaultValues: { code: '' },
  });

  const recoverForm = useForm<RecoverFormData>({
    resolver: zodResolver(recoverSchema),
    defaultValues: { email: '' },
  });

  const updatePasswordForm = useForm<UpdatePasswordFormData>({
    resolver: zodResolver(updatePasswordSchema),
    defaultValues: { password: '', confirmPassword: '' },
  });

  const handleLogin = async (data: LoginFormData, totpCode?: string, isBackupCode?: boolean) => {
    setLoading(true);
    try {
      // Try OPAQUE first (password never leaves client)
      const opaqueSession = await tryOpaqueLogin(data, totpCode, isBackupCode);
      if (opaqueSession === 'legacy') {
        // Fallback to legacy auth-session (Argon2id over TLS)
        return await legacyLogin(data, totpCode, isBackupCode);
      }
      if (opaqueSession === '2fa') {
        return; // 2FA modal shown
      }
      if (opaqueSession) {
        await applyAuthenticatedSession({
          access_token: opaqueSession.access_token,
          refresh_token: opaqueSession.refresh_token || '',
        });
        setShow2FAModal(false);
        setPendingLoginData(null);
        toast({ title: t('common.success'), description: t('auth.success') });
        navigate(postAuthRedirectPath, { replace: true });
        return true;
      }
      throw new Error('Login failed');
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('auth.errors.invalidCredentials'),
      });
      return false;
    } finally {
      if (!show2FAModal) setLoading(false);
    }
  };

  /**
   * Attempts OPAQUE login. Returns session object, 'legacy' if user needs legacy auth,
   * '2fa' if 2FA is required, or null on failure.
   */
  const tryOpaqueLogin = async (
    data: LoginFormData,
    totpCode?: string,
    isBackupCode?: boolean,
  ): Promise<Session | 'legacy' | '2fa' | null> => {
    try {
      // Step 1: Client starts login (password is blinded, never sent)
      const { clientLoginState, startLoginRequest } = await opaqueClient.startLogin(data.password);

      // Step 2: Send blinded request to server
      const startRes = await fetch(`${API_URL}/auth-opaque`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({
          action: 'login-start',
          userIdentifier: data.email,
          startLoginRequest,
        }),
      });

      if (!startRes.ok) {
        const errData = await startRes.json().catch(() => ({}));
        if (errData.useLegacy) return 'legacy';
        throw new Error('OPAQUE login-start failed');
      }

      const { loginResponse, loginId } = await startRes.json();

      // Step 3: Client finishes login (derives session key locally)
      const { finishLoginRequest } = await opaqueClient.finishLogin(
        clientLoginState,
        loginResponse,
        data.password,
      );

      // Step 4: Send proof to server (password was NEVER sent)
      // loginId is an opaque reference — serverLoginState stays server-side
      const finishRes = await fetch(`${API_URL}/auth-opaque`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({
          action: 'login-finish',
          userIdentifier: data.email,
          finishLoginRequest,
          loginId,
          skipCookie: !usesCookieSession,
        }),
      });

      if (!finishRes.ok) throw new Error('OPAQUE login-finish failed');

      const result = await finishRes.json();

      if (result.requires2FA) {
        setPendingLoginData(data);
        setShow2FAModal(true);
        return '2fa';
      }

      return result.session;
    } catch {
      // OPAQUE failed — fall back to legacy
      return 'legacy';
    }
  };

  /**
   * Legacy login path: sends password over TLS to auth-session (Argon2id verification).
   * Used for users who haven't migrated to OPAQUE yet.
   */
  const legacyLogin = async (
    data: LoginFormData,
    totpCode?: string,
    isBackupCode?: boolean,
  ): Promise<boolean> => {
    const bodyPayload: Record<string, unknown> = {
      email: data.email,
      password: data.password,
      totpCode,
      isBackupCode,
    };
    if (!usesCookieSession) {
      bodyPayload.skipCookie = true;
    }

    const res = await fetch(`${API_URL}/auth-session`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
      },
      credentials: usesCookieSession ? 'include' : 'omit',
      body: JSON.stringify(bodyPayload),
    });

    if (!res.ok) throw new Error('Invalid credentials');

    const { session, requires2FA } = await res.json();

    if (requires2FA) {
      setPendingLoginData(data);
      setShow2FAModal(true);
      return true;
    }

    if (session) {
      await applyAuthenticatedSession({
        access_token: session.access_token,
        refresh_token: session.refresh_token || '',
      });

      // Auto-migrate to OPAQUE after successful legacy login
      migrateToOpaque(data.email, data.password).catch(() => {
        // Silent failure — migration will retry on next login
      });
    }

    setShow2FAModal(false);
    setPendingLoginData(null);
    toast({ title: t('common.success'), description: t('auth.success') });
    navigate(postAuthRedirectPath, { replace: true });
    return true;
  };

  /**
   * Automatically migrates a legacy user to OPAQUE after successful Argon2id login.
   * Runs in background — failure is non-critical.
   */
  const migrateToOpaque = async (email: string, password: string): Promise<void> => {
    try {
      // Migration requires an active Supabase session (just established by legacyLogin)
      const { data: sessionData } = await supabase.auth.getSession();
      const accessToken = sessionData.session?.access_token;
      if (!accessToken) return; // No session, skip migration

      const { clientRegistrationState, registrationRequest } = await opaqueClient.startRegistration(password);

      const startRes = await fetch(`${API_URL}/auth-opaque`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          action: 'register-start',
          userIdentifier: email,
          registrationRequest,
        }),
      });

      if (!startRes.ok) return;
      const { registrationResponse } = await startRes.json();

      const { registrationRecord } = await opaqueClient.finishRegistration(
        clientRegistrationState,
        registrationResponse,
        password,
      );

      await fetch(`${API_URL}/auth-opaque`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          action: 'register-finish',
          userIdentifier: email,
          registrationRecord,
        }),
      });
    } catch {
      // Non-critical — will retry on next login
    }
  };

  const handle2FAVerify = async (code: string, isBackupCode: boolean) => {
    if (!pendingLoginData) return false;
    return await handleLogin(pendingLoginData, code, isBackupCode);
  };

  const handleSignup = async (data: SignupFormData) => {
    setLoading(true);
    try {
      // Full password check (strength + HIBP) before submitting
      const checkResult = await passwordCheck.onPasswordSubmit(data.password);
      if (!checkResult.isAcceptable) {
        toast({
          variant: 'destructive',
          title: t('common.error'),
          description: checkResult.isPwned
            ? t('passwordStrength.pwned', { count: checkResult.pwnedCount })
            : t('passwordStrength.veryWeak'),
        });
        setLoading(false);
        return;
      }
      const res = await fetch(`${API_URL}/auth-register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({ email: data.email, password: data.password })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Registration failed');
      }

      const responseData = await res.json();

      if (responseData.message === "User exists") {
        // User Enumeration Prevention: Fake success, but don't ask for OTP if they already exist, 
        // OR ask for OTP but it will fail. Better to just reset or show generic message.
        // Actually, if we require verify, let's just show verify to not leak existence.
        setMode('verify_signup');
        toast({
          title: t('common.success'),
          description: 'Bitte gib den 8-stelligen Code ein, der dir per E-Mail gesendet wurde.',
        });
      } else {
        setMode('verify_signup');
        toast({
          title: t('common.success'),
          description: 'Bitte gib den 8-stelligen Code ein, den wir dir soeben gesendet haben.',
        });
      }
    } catch (error: unknown) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: error instanceof Error ? error.message : 'Ein Fehler ist aufgetreten. Bitte versuche es später erneut.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifySignup = async (data: VerifySignupFormData) => {
    setLoading(true);
    try {
      const email = signupForm.getValues('email');
      const password = signupForm.getValues('password'); // Needed for auto-login

      // 1. Verify OTP with Supabase GoTrue
      const { data: verifyData, error: verifyError } = await supabase.auth.verifyOtp({
        email,
        token: data.code,
        type: 'signup'
      });

      if (verifyError || !verifyData.session) {
        throw new Error('Ungültiger oder abgelaufener Code.');
      }

      // 2. We now have a session! Since we use BFF HttpOnly cookies, we should
      // login via Edge Function to set the cookie. We can use the handleLogin helper 
      // with the credentials we saved in the form.
      await handleLogin({ email, password });

    } catch (error: unknown) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: error instanceof Error ? error.message : 'Verifizierung fehlgeschlagen.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleRecover = async (data: RecoverFormData) => {
    setLoading(true);
    try {
      await fetch(`${API_URL}/auth-recovery`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({ email: data.email })
      });

      // User Enumeration Prevention: Timing Attack Safe Response
      toast({
        title: 'E-Mail gesendet',
        description: 'Falls ein Konto mit dieser E-Mail existiert, haben wir einen Code zum Zurücksetzen gesendet.',
      });
      setMode('verify_recover');
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Ein Fehler ist aufgetreten.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyRecover = async (data: VerifyRecoverFormData) => {
    setLoading(true);
    try {
      const email = recoverForm.getValues('email');

      // Verify recovery code via our custom auth-recovery endpoint
      const res = await fetch(`${API_URL}/auth-recovery`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({ email, action: 'verify', code: data.code })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Ungültiger oder abgelaufener Code.');
      }

      const { session } = await res.json();

      // Session setzen für das Passwort-Update
      if (session) {
        await applyAuthenticatedSession({
          access_token: session.access_token,
          refresh_token: session.refresh_token || '',
        });
      }

      setMode('update_password');
      toast({
        title: t('common.success'),
        description: 'Code verifiziert. Bitte gib ein neues Passwort ein.',
      });
    } catch (error: unknown) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: error instanceof Error ? error.message : 'Verifizierung fehlgeschlagen.',
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePassword = async (data: UpdatePasswordFormData) => {
    setLoading(true);
    try {
      // WICHTIG: GoTrue (Supabase) liest den Hash (#access_token=...) und erzeugt daraus eine
      // valide Session. Wir nutzen diese, um unser Backend zu autorisieren!
      const { data: sessionData, error: sessionError } = await supabase.auth.getSession();

      if (sessionError || !sessionData.session) {
        throw new Error('Keine aktive Sitzung gefunden. Bitte den Link erneut anfordern.');
      }

      const res = await fetch(`${API_URL}/auth-reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${sessionData.session.access_token}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({ newPassword: data.password })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Reset failed');
      }

      toast({ title: t('common.success'), description: 'Passwort erfolgreich aktualisiert.' });
      navigate('/vault');

    } catch (error: unknown) {
      toast({ variant: 'destructive', title: t('common.error'), description: error instanceof Error ? error.message : 'Fehler beim Aktualisieren des Passworts.' });
    } finally {
      setLoading(false);
    }
  };


  const handleOAuth = async (provider: 'google' | 'discord' | 'github') => {
    setLoading(true);
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: {
        redirectTo: getOAuthRedirectUrl(),
      }
    });

    if (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('auth.errors.generic'),
      });
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex overflow-hidden">
      <SEO title="Anmelden / Registrieren" description="Melde dich bei Singra Vault an oder registriere dich." noIndex={true} />

      {/* ── Brand Panel (desktop only, left 45%) ────────────────── */}
      <div className="hidden lg:flex relative w-[45%] flex-shrink-0 overflow-hidden auth-brand-gradient auth-brand-reveal">
        <NebulaHeroBackground variant="panel" showText showParticles />

        {/* Floating accent particles */}
        <div aria-hidden="true" className="pointer-events-none absolute inset-0">
          {([
            { w: 6, h: 6, top: '18%', left: '22%', delay: '0s', dur: '7s' },
            { w: 4, h: 4, top: '64%', left: '14%', delay: '1.4s', dur: '6s' },
            { w: 8, h: 8, top: '38%', left: '72%', delay: '0.7s', dur: '8s' },
            { w: 3, h: 3, top: '78%', left: '55%', delay: '2.1s', dur: '6.5s' },
            { w: 5, h: 5, top: '12%', left: '68%', delay: '0.3s', dur: '7.5s' },
          ] as const).map((p, i) => (
            <div
              key={i}
              className="auth-particle"
              style={{
                width: p.w, height: p.h,
                top: p.top, left: p.left,
                animation: `auth-float ${p.dur} ease-in-out ${p.delay} infinite`,
              }}
            />
          ))}
        </div>

        {/* Brand info at bottom */}
        <div className="relative z-10 mt-auto p-12 space-y-5">
          <div className="flex items-center gap-3">
            <img src="/singra-icon.png" alt="Singra Vault" className="w-9 h-9 rounded-full shadow-lg shadow-primary/20 ring-1 ring-border/70" />
            <span className="text-lg font-semibold tracking-tight text-foreground/90">Singra Vault</span>
          </div>
          <ul className="space-y-2.5">
            {[
              'AES-256-GCM · Argon2id Key Derivation',
              'Zero-Knowledge — kein Klartext auf dem Server',
              'Post-Quantum ready mit @noble/post-quantum',
              'Schlüssel verlassen niemals dein Gerät',
            ].map((item) => (
              <li key={item} className="flex items-center gap-2.5 text-sm text-muted-foreground">
                <span className="h-1 w-1 rounded-full bg-primary/60 flex-shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* ── Form Panel (100% mobile / 55% desktop) ──────────────── */}
      <div className="flex-1 flex flex-col items-center justify-center p-6 md:p-12 auth-form-reveal relative">
        {/* Mobile logo */}
        <Link to="/" className="lg:hidden flex items-center gap-3 mb-10">
          <img src="/singra-icon.png" alt="Singra Vault" className="w-8 h-8 rounded-full shadow-lg shadow-primary/20 ring-1 ring-border/70" />
          <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-foreground to-foreground/80">Singra Vault</span>
        </Link>

        <div className="w-full max-w-sm">
          {/* Form header */}
          <div className="mb-8 text-center lg:text-left">
            <h1 className="text-2xl font-semibold text-foreground mb-1">
              {mode === 'login' ? t('auth.login.title')
                : mode === 'signup' ? t('auth.signup.title')
                  : mode === 'verify_signup' || mode === 'verify_recover' ? 'Code bestätigen'
                    : mode === 'update_password' ? 'Neues Passwort'
                      : 'Passwort vergessen'}
            </h1>
            <p className="text-sm text-muted-foreground">
              {mode === 'login' ? 'Willkommen zurück.'
                : mode === 'signup' ? 'Konto erstellen — kostenlos & sicher.'
                  : ''}
            </p>
          </div>

          <div className="auth-view-enter space-y-4">
            {/* OAuth Buttons */}
            {(mode === 'login' || mode === 'signup') && (
              <>
                <div className="grid grid-cols-3 gap-3 mb-6">
                  <Button variant="outline" onClick={() => handleOAuth('google')} disabled={loading} className="w-full">
                    <svg className="w-5 h-5" viewBox="0 0 24 24">
                      <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                      <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                      <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                      <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                    </svg>
                  </Button>
                  <Button variant="outline" onClick={() => handleOAuth('discord')} disabled={loading} className="w-full">
                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                    </svg>
                  </Button>
                  <Button variant="outline" onClick={() => handleOAuth('github')} disabled={loading} className="w-full">
                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
                    </svg>
                  </Button>
                </div>

                <div className="relative mb-6">
                  <Separator />
                  <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card px-2 text-xs text-muted-foreground">
                    {t(mode === 'login' ? 'auth.login.orContinueWith' : 'auth.signup.orContinueWith')}
                  </span>
                </div>
              </>
            )}

            {/* Update Password Form */}
            {mode === 'update_password' && (
              <Form {...updatePasswordForm}>
                <form onSubmit={updatePasswordForm.handleSubmit(handleUpdatePassword)} className="space-y-4">
                  {/* Remove the unnecessary email field for reset password, as identity comes from JWT */}
                  <FormField
                    control={updatePasswordForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Neues Passwort</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type={showPassword ? 'text' : 'password'} placeholder="••••••••••••" className="pl-10 pr-10" />
                            <Button type="button" variant="ghost" size="icon" className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7" onClick={() => setShowPassword(!showPassword)}>
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </Button>
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={updatePasswordForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Neues Passwort bestätigen</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="password" placeholder="••••••••••••" className="pl-10" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Passwort Speichern
                  </Button>
                </form>
              </Form>
            )}

            {/* Recover Form */}
            {mode === 'recover' && (
              <Form {...recoverForm}>
                <form onSubmit={recoverForm.handleSubmit(handleRecover)} className="space-y-4">
                  <FormField
                    control={recoverForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.login.email')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="email" placeholder="name@beispiel.de" className="pl-10" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Passwort zurücksetzen
                  </Button>
                </form>
              </Form>
            )}

            {/* Login Form */}
            {mode === 'login' && (
              <Form {...loginForm}>
                <form onSubmit={loginForm.handleSubmit((d) => handleLogin(d))} className="space-y-4">
                  <FormField
                    control={loginForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.login.email')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="email" placeholder="name@beispiel.de" className="pl-10" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={loginForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.login.password')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type={showPassword ? 'text' : 'password'} placeholder="••••••••••••" className="pl-10 pr-10" />
                            <Button type="button" variant="ghost" size="icon" className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7" onClick={() => setShowPassword(!showPassword)}>
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </Button>
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    {t('auth.login.submit')}
                  </Button>
                </form>
              </Form>
            )}

            {/* Signup Form */}
            {mode === 'signup' && (
              <Form {...signupForm}>
                <form onSubmit={signupForm.handleSubmit(handleSignup)} className="space-y-4">
                  <FormField
                    control={signupForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.signup.email')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="email" placeholder="name@beispiel.de" className="pl-10" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={signupForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.signup.password')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input
                              {...field}
                              type={showPassword ? 'text' : 'password'}
                              placeholder="••••••••••••"
                              className="pl-10 pr-10"
                              onFocus={passwordCheck.onFieldFocus}
                              onChange={(e) => {
                                field.onChange(e);
                                passwordCheck.onPasswordChange(e.target.value);
                              }}
                              onBlur={(e) => {
                                field.onBlur();
                                passwordCheck.onPasswordBlur(e.target.value);
                              }}
                            />
                            <Button type="button" variant="ghost" size="icon" className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7" onClick={() => setShowPassword(!showPassword)}>
                              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </Button>
                          </div>
                        </FormControl>
                        {passwordCheck.strengthResult && (
                          <PasswordStrengthMeter
                            score={passwordCheck.strengthResult.score}
                            feedback={passwordCheck.strengthResult.feedback}
                            crackTimeDisplay={passwordCheck.strengthResult.crackTimeDisplay}
                            isPwned={passwordCheck.pwnedResult?.isPwned ?? false}
                            pwnedCount={passwordCheck.pwnedResult?.pwnedCount ?? 0}
                            isChecking={passwordCheck.isChecking}
                          />
                        )}
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={signupForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.signup.confirmPassword')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="password" placeholder="••••••••••••" className="pl-10" />
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    {t('auth.signup.submit')}
                  </Button>
                </form>
              </Form>
            )}

            {/* Verify Signup Form */}
            {mode === 'verify_signup' && (
              <Form {...verifySignupForm}>
                <form onSubmit={verifySignupForm.handleSubmit(handleVerifySignup)} className="space-y-4">
                  <div className="text-sm text-muted-foreground mb-4 text-center">
                    Wir haben einen 8-stelligen Code an {signupForm.getValues('email') || 'deine E-Mail'} gesendet.
                  </div>
                  <FormField
                    control={verifySignupForm.control}
                    name="code"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Bestätigungscode</FormLabel>
                        <FormControl>
                          <Input {...field} type="text" placeholder="12345678" className="text-center tracking-widest text-lg" maxLength={8} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Code bestätigen
                  </Button>
                </form>
              </Form>
            )}

            {/* Verify Recover Form */}
            {mode === 'verify_recover' && (
              <Form {...verifyRecoverForm}>
                <form onSubmit={verifyRecoverForm.handleSubmit(handleVerifyRecover)} className="space-y-4">
                  <div className="text-sm text-muted-foreground mb-4 text-center">
                    Wir haben einen 8-stelligen Code an {recoverForm.getValues('email') || 'deine E-Mail'} gesendet.
                  </div>
                  <FormField
                    control={verifyRecoverForm.control}
                    name="code"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Bestätigungscode</FormLabel>
                        <FormControl>
                          <Input {...field} type="text" placeholder="12345678" className="text-center tracking-widest text-lg" maxLength={8} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    Code bestätigen
                  </Button>
                </form>
              </Form>
            )}

            {/* Toggle mode */}
            <div className="mt-6 text-center text-sm flex flex-col gap-2">
              {mode !== 'login' && (
                <button type="button" className="text-primary hover:underline font-medium" onClick={() => setMode('login')}>
                  Zurück zum Login
                </button>
              )}
              {mode === 'login' && (
                <>
                  <button type="button" className="text-primary hover:underline font-medium" onClick={() => setMode('signup')}>
                    {t('auth.login.signupLink')}
                  </button>
                  <button type="button" className="text-muted-foreground hover:underline font-medium" onClick={() => setMode('recover')}>
                    Passwort vergessen?
                  </button>
                </>
              )}
            </div>
          </div>{/* end auth-view-enter */}
        </div>{/* end max-w-sm */}
      </div>{/* end form panel */}

      <TwoFactorVerificationModal
        open={show2FAModal}
        onVerify={handle2FAVerify}
        onCancel={() => {
          setShow2FAModal(false);
          setPendingLoginData(null);
          setLoading(false);
        }}
      />
    </div>
  );
}
