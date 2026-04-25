// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authentication Page
 * 
 * Handles login, passkey, and signup flows via Custom Edge Functions (BFF Pattern).
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate, useSearchParams, Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { createClient, type Session } from '@supabase/supabase-js';
import { Mail, Lock, Eye, EyeOff, Loader2, ClipboardPaste, Link2, WandSparkles } from 'lucide-react';
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { BrandMedia } from '@/components/BrandMedia';
import { DesktopOAuthBridgeView } from '@/components/auth/DesktopOAuthBridgeView';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { TwoFactorVerificationModal } from '@/components/auth/TwoFactorVerificationModal';
import { supabase } from '@/integrations/supabase/client';
import { SEO } from '@/components/SEO';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import { resolvePostAuthRedirectPath } from '@/services/postAuthRedirectService';
import { applyAuthenticatedSession, clearPersistentSession, persistAuthenticatedSession } from '@/services/authSessionManager';
import { getInitialDeepLinks, listenForDeepLinks } from '@/platform/deepLink';
import { getOAuthRedirectUrl } from '@/platform/oauthRedirect';
import {
  getSupabaseCallbackType,
  isBlockedSupabaseAuthCallback,
  isDesktopOAuthBridgeUrl,
  isTauriOAuthCallbackUrl,
  normalizeOAuthCallbackInput,
  parseOAuthCallbackPayload,
} from '@/platform/tauriOAuthCallback';
import { isTauriRuntime } from '@/platform/runtime';
import { openExternalUrl } from '@/platform/openExternalUrl';
import { createDesktopOAuthUrl, exchangeDesktopOAuthCode, type DesktopOAuthProvider } from '@/platform/desktopOAuth';
import { runtimeConfig } from '@/config/runtimeConfig';
import * as opaqueClient from '@/services/opaqueService';
import {
  completeOpaqueAccountPasswordReset,
  requestAccountPasswordEmailCode,
  verifyAccountPasswordEmailCode,
  verifyAccountPasswordResetSecondFactor,
} from '@/services/accountPasswordResetService';
import { DEFAULT_PASSWORD_OPTIONS, generatePassword } from '@/services/passwordGenerator';

const emailFieldSchema = z.preprocess(
  (value) => typeof value === 'string' ? opaqueClient.normalizeOpaqueIdentifier(value) : value,
  z.string().email('auth.errors.invalidEmail'),
);

const loginSchema = z.object({
  email: emailFieldSchema,
  password: z.string().min(1, 'auth.errors.invalidCredentials'),
});

const signupSchema = z.object({
  email: emailFieldSchema,
  // NIST 800-63B Mindestlänge von 12 Zeichen
  password: z.string().min(12, 'Passwort muss mindestens 12 Zeichen haben.'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'auth.errors.passwordMismatch',
  path: ['confirmPassword'],
});

const recoverSchema = z.object({
  email: emailFieldSchema,
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
type ParsedOAuthCallbackPayload = NonNullable<ReturnType<typeof parseOAuthCallbackPayload>>;

const processedCallbackKeys = new Set<string>();
const AUTH_PANEL_VIDEO_SOURCES = [
  { src: '/brand/auth-panel.webm', type: 'video/webm' },
  { src: '/brand/auth-panel.mp4', type: 'video/mp4' },
];

export default function Auth() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();
  const { user, authReady, authMode } = useAuth();

  const urlToken = searchParams.get('token');
  const [mode, setMode] = useState<'login' | 'signup' | 'verify_signup' | 'recover' | 'verify_recover' | 'update_password'>(
    urlToken ? 'update_password' :
      searchParams.get('mode') === 'signup' ? 'signup' :
        searchParams.get('mode') === 'recover' ? 'recover' : 'login'
  );
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [passwordResetToken, setPasswordResetToken] = useState<string | null>(null);
  const [manualDeepLinkOpen, setManualDeepLinkOpen] = useState(false);
  const [manualDeepLinkValue, setManualDeepLinkValue] = useState('');
  const [manualDeepLinkSubmitting, setManualDeepLinkSubmitting] = useState(false);
  const isDesktopBridgePage = !isTauriRuntime() && isDesktopOAuthBridgeUrl(window.location.href, window.location.origin);
  const postAuthRedirectPath = resolvePostAuthRedirectPath(searchParams.get('redirect'), location.state);
  const API_URL = runtimeConfig.supabaseFunctionsUrl ?? `${runtimeConfig.supabaseUrl}/functions/v1`;
  const inIframe = (() => {
    try { return window.self !== window.top; } catch { return true; }
  })();
  const usesCookieSession = !inIframe && !isTauriRuntime();

  const authCallbackRuntimeRef = useRef({ API_URL, mode, navigate, postAuthRedirectPath, usesCookieSession, t, toast });
  const pendingCallbacks = useRef(new Set<string>());
  const settledCallbacks = useRef(new Set<string>());
  const notifiedCallbacks = useRef(new Set<string>());

  useEffect(() => {
    authCallbackRuntimeRef.current = { API_URL, mode, navigate, postAuthRedirectPath, usesCookieSession, t, toast };
  }, [API_URL, mode, navigate, postAuthRedirectPath, t, toast, usesCookieSession]);

  const applyCallbackSession = useCallback(async (callbackUrl: string): Promise<boolean> => {
    const callbackPayload = parseOAuthCallbackPayload(callbackUrl, window.location.origin);
    if (!callbackPayload?.hasAuthPayload) {
      if (isTauriOAuthCallbackUrl(callbackUrl)) {
        const callbackKey = `empty:${callbackUrl}`;
        console.warn('[Auth] Tauri OAuth callback arrived without auth payload.');
        const { t: translate, toast: showToast } = authCallbackRuntimeRef.current;
        notifyCallbackFailure(notifiedCallbacks.current, callbackKey, () => {
          showToast({
            variant: 'destructive',
            title: translate('common.error'),
            description: translate('auth.errors.generic'),
          });
        });
        setLoading(false);
      }

      return false;
    }

    const callbackKey = getCallbackKey(callbackUrl, callbackPayload);
    if (processedCallbackKeys.has(callbackKey)) {
      return true;
    }

    if (isDesktopBridgeCallback(callbackPayload)) {
      return false;
    }

    if (isBlockedSupabaseAuthCallback(callbackPayload)) {
      settledCallbacks.current.add(callbackKey);
      processedCallbackKeys.add(callbackKey);
      const callbackType = getSupabaseCallbackType(callbackPayload);
      console.warn('[Auth] Blocked direct Supabase auth callback:', callbackType ?? 'unknown');
      await supabase.auth.signOut().catch(() => undefined);
      await clearPersistentSession();
      cleanAuthCallbackUrl();
      setLoading(false);
      setMode(callbackType === 'recovery' ? 'recover' : 'login');
      const { t: translate, toast: showToast } = authCallbackRuntimeRef.current;
      notifyCallbackFailure(notifiedCallbacks.current, callbackKey, () => {
        showToast({
          variant: 'destructive',
          title: translate('common.error'),
          description: translate('auth.errors.generic'),
        });
      });
      return false;
    }

    if (callbackPayload.error) {
      if (settledCallbacks.current.has(callbackKey)) {
        return false;
      }

      settledCallbacks.current.add(callbackKey);
      console.error('[Auth] OAuth callback returned an error:', callbackPayload.error);
      const { t: translate, toast: showToast } = authCallbackRuntimeRef.current;
      notifyCallbackFailure(notifiedCallbacks.current, callbackKey, () => {
        showToast({
          variant: 'destructive',
          title: translate('common.error'),
          description: callbackPayload.error?.description ?? callbackPayload.error?.error ?? translate('auth.errors.generic'),
        });
      });
      setLoading(false);
      return false;
    }

    if (pendingCallbacks.current.has(callbackKey) || settledCallbacks.current.has(callbackKey)) {
      return true;
    }

    pendingCallbacks.current.add(callbackKey);
    setLoading(true);

    try {
      console.info('[Auth] Applying OAuth callback session...');
      const session = callbackPayload.tokens
        ? await applyAuthenticatedSession(callbackPayload.tokens)
        : isTauriRuntime()
          ? await exchangeDesktopOAuthCodeForSession(callbackPayload)
          : await exchangeOAuthCodeForSession(callbackPayload.code);

      if (!session) {
        setLoading(false);
        return false;
      }

      const {
        API_URL: authApiUrl,
        mode: currentMode,
        navigate: goToPostAuthPath,
        postAuthRedirectPath: redirectPath,
        usesCookieSession: shouldUseCookieSession,
      } = authCallbackRuntimeRef.current;

      if (shouldUseCookieSession) {
        const syncResponse = await fetch(`${authApiUrl}/auth-session`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${session.access_token}`,
          },
          credentials: 'include',
          body: JSON.stringify({
            action: 'oauth-sync',
            refreshToken: session.refresh_token,
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

      settledCallbacks.current.add(callbackKey);
      processedCallbackKeys.add(callbackKey);
      console.info('[Auth] OAuth callback session applied.');
      setLoading(false);
      if (currentMode !== 'update_password') {
        goToPostAuthPath(redirectPath, { replace: true });
      }
      return true;
    } catch (err) {
      settledCallbacks.current.add(callbackKey);
      console.error('[Auth] Failed to apply OAuth callback session:', err);
      const { t: translate, toast: showToast } = authCallbackRuntimeRef.current;
      notifyCallbackFailure(notifiedCallbacks.current, callbackKey, () => {
        showToast({
          variant: 'destructive',
          title: translate('common.error'),
          description: translate('auth.errors.generic'),
        });
      });
      setLoading(false);
      return false;
    } finally {
      pendingCallbacks.current.delete(callbackKey);
      cleanAuthCallbackUrl();
    }
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | null = null;

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
      unlisten?.();
    };
  }, [applyCallbackSession]);

  useEffect(() => {
    if (!authReady) {
      return;
    }

    if (user && authMode === 'online' && mode !== 'update_password') {
      navigate(postAuthRedirectPath, { replace: true });
    }
  }, [authMode, authReady, user, mode, navigate, postAuthRedirectPath]);

  const [show2FAModal, setShow2FAModal] = useState(false);
  const [twoFactorMode, setTwoFactorMode] = useState<'login' | 'password-reset' | null>(null);
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
    let requiresTwoFactor = false;
    try {
      const opaqueSession = await tryOpaqueLogin(data, totpCode, isBackupCode);
      if (opaqueSession === '2fa') {
        requiresTwoFactor = true;
        return;
      }

      await applyAuthenticatedSession({
        access_token: opaqueSession.access_token,
        refresh_token: opaqueSession.refresh_token || '',
      });
      setShow2FAModal(false);
      setTwoFactorMode(null);
      setPendingLoginData(null);
      toast({ title: t('common.success'), description: t('auth.success') });
      navigate(postAuthRedirectPath, { replace: true });
      return true;
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('auth.errors.invalidCredentials'),
      });
      return false;
    } finally {
      if (!requiresTwoFactor) {
        setLoading(false);
      }
    }
  };
  /**
   * Attempts OPAQUE login. OPAQUE failures abort the login; there is no legacy fallback.
   */
  const tryOpaqueLogin = async (
    data: LoginFormData,
    totpCode?: string,
    isBackupCode?: boolean,
  ): Promise<Session | '2fa'> => {
    opaqueClient.assertOpaqueServerKeyPinConfigured();
    const userIdentifier = opaqueClient.normalizeOpaqueIdentifier(data.email);
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
        userIdentifier,
        startLoginRequest,
      }),
    });

    if (!startRes.ok) {
      throw new Error('OPAQUE login-start failed');
    }

    const { loginResponse, loginId } = await startRes.json();

    // Step 3: Client finishes login (derives session key locally)
    const { finishLoginRequest, sessionKey } = await opaqueClient.finishLogin(
      clientLoginState,
      loginResponse,
      data.password,
    );

    // Step 4: Send proof to server (password was NEVER sent)
    // loginId is an opaque reference - serverLoginState stays server-side
    const finishRes = await fetch(`${API_URL}/auth-opaque`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`,
      },
      credentials: usesCookieSession ? 'include' : 'omit',
      body: JSON.stringify({
        action: 'login-finish',
        userIdentifier,
        finishLoginRequest,
        loginId,
        totpCode,
        isBackupCode,
        skipCookie: !usesCookieSession,
      }),
    });

    if (!finishRes.ok) throw new Error('OPAQUE login-finish failed');

    const result = await finishRes.json();

    if (result.requires2FA) {
      setPendingLoginData(data);
      setTwoFactorMode('login');
      setShow2FAModal(true);
      return '2fa';
    }

    if (!result.session) {
      throw new Error('OPAQUE login did not return a session');
    }

    await opaqueClient.verifyOpaqueSessionBinding(sessionKey, result.session, result.opaqueSessionBinding);
    return result.session;
  };


  const handle2FAVerify = async (code: string, isBackupCode: boolean) => {
    if (twoFactorMode === 'password-reset') {
      return await handlePasswordReset2FAVerify(code, isBackupCode);
    }

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

      opaqueClient.assertOpaqueServerKeyPinConfigured();
      const userIdentifier = opaqueClient.normalizeOpaqueIdentifier(data.email);
      signupForm.setValue('email', userIdentifier);
      const { clientRegistrationState, registrationRequest } = await opaqueClient.startRegistration(data.password);
      const res = await fetch(`${API_URL}/auth-register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({ email: userIdentifier, registrationRequest })
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Registration failed');
      }

      const { registrationId, registrationResponse } = await res.json();
      if (typeof registrationId !== 'string' || typeof registrationResponse !== 'string') {
        throw new Error('OPAQUE registration start failed');
      }

      const { registrationRecord } = await opaqueClient.finishRegistration(
        clientRegistrationState,
        registrationResponse,
        data.password,
      );

      const finishRes = await fetch(`${API_URL}/auth-register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${runtimeConfig.supabasePublishableKey}`
        },
        credentials: usesCookieSession ? 'include' : 'omit',
        body: JSON.stringify({
          action: 'finish',
          email: userIdentifier,
          registrationId,
          registrationRecord,
        })
      });

      if (!finishRes.ok) {
        const errorData = await finishRes.json().catch(() => ({}));
        throw new Error(errorData.error || 'OPAQUE registration finish failed');
      }

      setMode('verify_signup');
      toast({
        title: t('common.success'),
        description: 'Bitte gib den 8-stelligen Code ein, den wir dir soeben gesendet haben.',
      });
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
      const email = opaqueClient.normalizeOpaqueIdentifier(signupForm.getValues('email'));
      const password = signupForm.getValues('password'); // Needed for auto-login

      const { error: verifyError } = await createEphemeralSupabaseAuthClient().auth.verifyOtp({
        email,
        token: data.code,
        type: 'signup'
      });

      if (verifyError) {
        throw new Error('Ungültiger oder abgelaufener Code.');
      }

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
    setPasswordResetToken(null);
    try {
      const email = opaqueClient.normalizeOpaqueIdentifier(data.email);
      recoverForm.setValue('email', email);
      await requestAccountPasswordEmailCode({ purpose: 'forgot', email });

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
      const email = opaqueClient.normalizeOpaqueIdentifier(recoverForm.getValues('email'));
      const { resetToken, requires2FA } = await verifyAccountPasswordEmailCode({
        purpose: 'forgot',
        email,
        code: data.code,
      });

      setPasswordResetToken(resetToken);
      if (requires2FA) {
        setTwoFactorMode('password-reset');
        setShow2FAModal(true);
        toast({
          title: t('common.success'),
          description: 'Code verifiziert. Bitte bestätige jetzt deine Zwei-Faktor-Authentifizierung.',
        });
        return;
      }

      setMode('update_password');
      toast({
        title: t('common.success'),
        description: 'Code verifiziert. Bitte gib ein neues Passwort ein.',
      });
      return;
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

  const handlePasswordReset2FAVerify = async (code: string, isBackupCode: boolean) => {
    if (!passwordResetToken) return false;

    try {
      await verifyAccountPasswordResetSecondFactor({
        resetToken: passwordResetToken,
        code,
        isBackupCode,
      });
      setShow2FAModal(false);
      setTwoFactorMode(null);
      setMode('update_password');
      toast({
        title: t('common.success'),
        description: '2FA bestätigt. Bitte gib ein neues Passwort ein.',
      });
      return true;
    } catch {
      return false;
    }
  };

  const handleUpdatePassword = async (data: UpdatePasswordFormData) => {
    setLoading(true);
    try {
      if (!passwordResetToken) {
        throw new Error('Keine gültige Reset-Berechtigung gefunden. Bitte fordere einen neuen Code an.');
      }

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

      await completeOpaqueAccountPasswordReset({
        resetToken: passwordResetToken,
        newPassword: data.password,
      });

      toast({ title: t('common.success'), description: 'Passwort erfolgreich aktualisiert.' });
      setPasswordResetToken(null);
      updatePasswordForm.reset();
      setMode('login');
      navigate('/auth', { replace: true });

    } catch (error: unknown) {
      toast({ variant: 'destructive', title: t('common.error'), description: error instanceof Error ? error.message : 'Fehler beim Aktualisieren des Passworts.' });
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateUpdatePassword = () => {
    const generatedPassword = generatePassword(DEFAULT_PASSWORD_OPTIONS);
    updatePasswordForm.setValue('password', generatedPassword, { shouldDirty: true, shouldValidate: true });
    updatePasswordForm.setValue('confirmPassword', generatedPassword, { shouldDirty: true, shouldValidate: true });
    passwordCheck.onPasswordChange(generatedPassword);
    passwordCheck.onPasswordBlur(generatedPassword);
  };

  const handleOAuth = async (provider: DesktopOAuthProvider) => {
    setLoading(true);

    try {
      const isTauri = isTauriRuntime();
      if (isTauri) {
        await openExternalUrl(await createDesktopOAuthUrl(provider));
        return;
      }

      const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo: getOAuthRedirectUrl(),
        }
      });

      if (error) throw error;
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('auth.errors.generic'),
      });
    } finally {
      // For Tauri, we keep the loading state until the deep link arrives 
      // or the user manually interacts again. For Web, the redirect happens anyway.
      if (!isTauriRuntime()) {
        setLoading(false);
      }
    }
  };

  const handlePasteManualDeepLink = async () => {
    if (!navigator.clipboard?.readText) {
      return;
    }

    try {
      setManualDeepLinkValue(await navigator.clipboard.readText());
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Die Zwischenablage konnte nicht gelesen werden.',
      });
    }
  };

  const handleManualDeepLinkSubmit = async () => {
    const link = manualDeepLinkValue.trim();
    if (!link) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Bitte füge einen vollständigen Anmelde-Link ein.',
      });
      return;
    }

    const callbackUrl = normalizeOAuthCallbackInput(link, runtimeConfig.webUrl);
    if (!callbackUrl) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Der eingefügte Link enthält keinen gültigen Anmelde-Callback.',
      });
      return;
    }

    setManualDeepLinkSubmitting(true);
    try {
      const applied = await applyCallbackSession(callbackUrl);
      if (applied) {
        setManualDeepLinkOpen(false);
        setManualDeepLinkValue('');
      }
    } finally {
      setManualDeepLinkSubmitting(false);
    }
  };

  if (isDesktopBridgePage) {
    return <DesktopOAuthBridgeView />;
  }

  return (
    <div className="min-h-screen flex overflow-hidden">
      <SEO title="Anmelden / Registrieren" description="Melde dich bei Singra Vault an oder registriere dich." noIndex={true} />

      {/* ── Brand Panel (desktop only, left 45%) ────────────────── */}
      <div className="hidden lg:flex relative w-[45%] flex-shrink-0 overflow-hidden auth-visual-panel auth-brand-reveal" aria-hidden="true">
        <BrandMedia
          alt=""
          fallbackImageSrc="/brand/auth-panel.png"
          animatedImageSrc="/brand/auth-panel.gif"
          videoSources={AUTH_PANEL_VIDEO_SOURCES}
          width={1122}
          height={1402}
          frameClassName="auth-visual-frame"
          mediaClassName="auth-visual-image"
        />
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
                  <Button variant="outline" onClick={() => handleOAuth('google')} disabled={loading} className="w-full" aria-label="Google Login" title="Google Login">
                    <svg className="w-5 h-5" viewBox="0 0 24 24">
                      <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                      <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                      <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                      <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                    </svg>
                  </Button>
                  <Button variant="outline" onClick={() => handleOAuth('discord')} disabled={loading} className="w-full" aria-label="Discord Login" title="Discord Login">
                    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z" />
                    </svg>
                  </Button>
                  <Button variant="outline" onClick={() => handleOAuth('github')} disabled={loading} className="w-full" aria-label="GitHub Login" title="GitHub Login">
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
                  <p className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-100">
                    Das Kontopasswort setzt nur den Login neu. Es entschlüsselt keinen Vault und stellt keinen verlorenen Vault-Key wieder her.
                  </p>
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={handleGenerateUpdatePassword}
                  >
                    <WandSparkles className="w-4 h-4 mr-2" />
                    {t('settings.password.generateButton')}
                  </Button>
                  <FormField
                    control={updatePasswordForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Neues Passwort</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input
                              {...field}
                              type={showPassword ? 'text' : 'password'}
                              placeholder="••••••••••••"
                              className="pl-10 pr-10"
                              onFocus={passwordCheck.onFieldFocus}
                              onChange={(event) => {
                                field.onChange(event);
                                passwordCheck.onPasswordChange(event.target.value);
                              }}
                              onBlur={(event) => {
                                field.onBlur();
                                passwordCheck.onPasswordBlur(event.target.value);
                              }}
                            />
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
                  <Button type="submit" className="w-full" disabled={loading || passwordCheck.isChecking}>
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
                  <p className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-100">
                    Der Reset ändert nur den Account-Login. Ohne deinen Vault-Key können verschlüsselte Vault-Daten nicht wiederhergestellt werden.
                  </p>
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
              {isTauriRuntime() && (
                <button type="button" className="text-muted-foreground hover:underline font-medium mb-2" onClick={() => setManualDeepLinkOpen(true)}>
                  Anmelde-Link manuell einfügen
                </button>
              )}
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
          setTwoFactorMode(null);
          setPendingLoginData(null);
          if (twoFactorMode === 'password-reset') {
            setPasswordResetToken(null);
          }
          setLoading(false);
        }}
      />

      <Dialog open={manualDeepLinkOpen} onOpenChange={setManualDeepLinkOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Link2 className="h-4 w-4" />
              Anmelde-Link einfügen
            </DialogTitle>
            <DialogDescription>
              Füge den vollständigen Link aus dem Browser ein, falls die automatische Übergabe an die Desktop-App nicht greift.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <Textarea
              value={manualDeepLinkValue}
              onChange={(event) => setManualDeepLinkValue(event.target.value)}
              placeholder="singravault://auth/callback?... oder https://singravault.mauntingstudios.de/auth?..."
              className="min-h-28 resize-y"
            />
            <p className="text-xs text-muted-foreground">
              Unterstützt sowohl den Rohlink aus der Browser-Seite als auch den vollständigen Callback-Link.
            </p>
          </div>

          <DialogFooter className="gap-2 sm:justify-between">
            <Button
              type="button"
              variant="outline"
              onClick={() => void handlePasteManualDeepLink()}
            >
              <ClipboardPaste className="w-4 h-4 mr-2" />
              Aus Zwischenablage
            </Button>
            <Button
              type="button"
              onClick={() => void handleManualDeepLinkSubmit()}
              disabled={manualDeepLinkSubmitting}
            >
              {manualDeepLinkSubmitting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Anmeldung fortsetzen
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

async function exchangeOAuthCodeForSession(code: string | null): Promise<Session | null> {
  if (!code) {
    return null;
  }

  const { data, error } = await supabase.auth.exchangeCodeForSession(code);
  if (error || !data.session?.access_token || !data.session.refresh_token) {
    throw error ?? new Error('OAuth code exchange did not return a session');
  }

  await persistAuthenticatedSession(data.session);
  return data.session;
}

function createEphemeralSupabaseAuthClient() {
  return createClient(runtimeConfig.supabaseUrl, runtimeConfig.supabasePublishableKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    },
  });
}

async function exchangeDesktopOAuthCodeForSession(payload: ParsedOAuthCallbackPayload): Promise<Session> {
  const tokens = await exchangeDesktopOAuthCode({
    code: payload.code,
    flowId: payload.params.get('desktop_oauth_flow'),
    state: payload.params.get('state'),
  });
  return applyAuthenticatedSession(tokens);
}

function isDesktopBridgeCallback(payload: ParsedOAuthCallbackPayload): boolean {
  return !isTauriRuntime() && payload.params.get('source') === 'tauri';
}

function getCallbackKey(callbackUrl: string, payload: ParsedOAuthCallbackPayload): string {
  if (payload.tokens) {
    return `tokens:${payload.tokens.access_token}:${payload.tokens.refresh_token}`;
  }

  if (payload.code) {
    return `code:${payload.code}`;
  }

  const errorKey = payload.error?.errorCode ?? payload.error?.error;
  if (errorKey) {
    return `error:${errorKey}:${payload.error?.description ?? ''}`;
  }

  return callbackUrl;
}

function notifyCallbackFailure(
  notifiedCallbacks: Set<string>,
  callbackKey: string,
  notify: () => void,
): void {
  if (notifiedCallbacks.has(callbackKey)) {
    return;
  }

  notifiedCallbacks.add(callbackKey);
  notify();
}

function cleanAuthCallbackUrl(): void {
  if (typeof window === 'undefined') {
    return;
  }

  const payload = parseOAuthCallbackPayload(window.location.href, window.location.origin);
  if (!payload?.hasAuthPayload) {
    return;
  }

  const cleanSearch = new URLSearchParams(window.location.search);
  [
    'access_token',
    'refresh_token',
    'expires_at',
    'expires_in',
    'token_type',
    'type',
    'code',
    'error',
    'error_code',
    'error_description',
    'provider_token',
    'provider_refresh_token',
  ].forEach((key) => cleanSearch.delete(key));

  const cleanUrl = `${window.location.pathname}${cleanSearch.toString() ? `?${cleanSearch.toString()}` : ''}`;
  window.history.replaceState({}, document.title, cleanUrl);
}
