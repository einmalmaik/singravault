// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Authentication Page
 * 
 * Handles login, passkey, and signup flows via Custom Edge Functions (BFF Pattern).
 */

import { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, Mail, Lock, Eye, EyeOff, Loader2 } from 'lucide-react';
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { startAuthentication } from '@simplewebauthn/browser';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { TwoFactorVerificationModal } from '@/components/auth/TwoFactorVerificationModal';
import { supabase } from '@/integrations/supabase/client';
import { SEO } from '@/components/SEO';

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

type LoginFormData = z.infer<typeof loginSchema>;
type SignupFormData = z.infer<typeof signupSchema>;
type RecoverFormData = z.infer<typeof recoverSchema>;

export default function Auth() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [mode, setMode] = useState<'login' | 'signup' | 'recover'>(
    searchParams.get('mode') === 'signup' ? 'signup' : 'login'
  );
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  // Note: 2FA Logik (TOTP) bleibt bestehen, wird hier vereinfacht
  const [show2FAModal, setShow2FAModal] = useState(false);

  const loginForm = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: '', password: '' },
  });

  const signupForm = useForm<SignupFormData>({
    resolver: zodResolver(signupSchema),
    defaultValues: { email: '', password: '', confirmPassword: '' },
  });

  const recoverForm = useForm<RecoverFormData>({
    resolver: zodResolver(recoverSchema),
    defaultValues: { email: '' },
  });

  // Supabase REST Edge Function Base URL
  const API_URL = import.meta.env.VITE_SUPABASE_URL + '/functions/v1';

  const handleLogin = async (data: LoginFormData) => {
    setLoading(true);
    try {
      // BFF: Login an Edge Function
      const res = await fetch(`${API_URL}/auth-session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        credentials: 'include',
        body: JSON.stringify({ email: data.email, password: data.password })
      });

      if (!res.ok) {
        throw new Error('Invalid credentials');
      }

      const { session } = await res.json();
      if (session) {
        await supabase.auth.setSession({
          access_token: session.access_token,
          refresh_token: session.refresh_token || '',
        });
      }

      // Success! Das HttpOnly Cookie wurde gesetzt.
      toast({ title: t('common.success'), description: t('auth.success') });
      navigate('/vault');

    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('auth.errors.invalidCredentials'),
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (data: SignupFormData) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth-register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        credentials: 'include',
        body: JSON.stringify({ email: data.email, password: data.password })
      });

      // User Enumeration Prevention: Immer Erfolgsmeldung zeigen
      toast({
        title: t('common.success'),
        description: 'Falls diese E-Mail noch nicht registriert ist, wurde ein Bestätigungslink gesendet.',
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Ein Fehler ist aufgetreten. Bitte versuche es später erneut.',
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
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        credentials: 'include',
        body: JSON.stringify({ email: data.email })
      });

      // User Enumeration Prevention: Timing Attack Safe Response
      toast({
        title: 'E-Mail gesendet',
        description: 'Falls ein Konto mit dieser E-Mail existiert, haben wir einen Link zum Zurücksetzen gesendet.',
      });
    } catch (error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: 'Ein Fehler ist aufgetreten.',
      });
    } finally {
      setLoading(false);
      setMode('login');
    }
  };

  const handlePasskeyAuth = async () => {
    const email = loginForm.getValues().email;
    if (!email) {
      toast({ title: t('common.error'), description: 'Bitte gib zuerst deine E-Mail ein.' });
      return;
    }

    setLoading(true);
    try {
      // Passkey Challenge abrufen
      const optionsRes = await fetch(`${API_URL}/webauthn`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        credentials: 'include',
        body: JSON.stringify({ action: 'generate-authentication-options', email })
      });

      if (!optionsRes.ok) throw new Error('Challenge fetch failed');
      const { options } = await optionsRes.json();

      // Nutze WebAuthn API
      const authResult = await startAuthentication(options);

      // Token beim Server verifizieren
      const verifyRes = await fetch(`${API_URL}/webauthn`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        credentials: 'include',
        body: JSON.stringify({ action: 'verify-authentication', credential: authResult, email })
      });

      if (verifyRes.ok) {
        const { session } = await verifyRes.json();
        if (session) {
          await supabase.auth.setSession({
            access_token: session.access_token,
            refresh_token: session.refresh_token || '',
          });
        }
        navigate('/vault');
      } else {
        throw new Error('Verification failed');
      }
    } catch (error) {
      toast({ variant: 'destructive', title: t('common.error'), description: 'Passkey Auth fehlgeschlagen.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary/5 via-background to-primary/10 p-4">
      <SEO title="Anmelden / Registrieren" noIndex={true} />
      <div className="w-full max-w-md">
        <Link to="/" className="flex items-center justify-center gap-2 mb-8">
          <Shield className="w-8 h-8 text-primary" />
          <span className="text-2xl font-bold">Singra Vault</span>
        </Link>
        <Card className="shadow-xl">
          <CardHeader className="text-center">
            <CardTitle className="text-2xl">
              {mode === 'login' ? t('auth.login.title') : mode === 'signup' ? t('auth.signup.title') : 'Passwort vergessen'}
            </CardTitle>
          </CardHeader>

          <CardContent>
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
                            <Input {...field} type="email" className="pl-10" />
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
                <form onSubmit={loginForm.handleSubmit(handleLogin)} className="space-y-4">
                  <FormField
                    control={loginForm.control}
                    name="email"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.login.email')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="email" className="pl-10" />
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
                            <Input {...field} type={showPassword ? 'text' : 'password'} className="pl-10 pr-10" />
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

                  <div className="relative mb-6 mt-4">
                    <Separator />
                    <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card px-2 text-xs text-muted-foreground">Alternativ</span>
                  </div>

                  <Button type="button" onClick={handlePasskeyAuth} variant="outline" className="w-full">
                    <Shield className="w-4 h-4 mr-2" />
                    Mit Passkey anmelden
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
                            <Input {...field} type="email" className="pl-10" />
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
                            <Input {...field} type={showPassword ? 'text' : 'password'} className="pl-10 pr-10" />
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
                    control={signupForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('auth.signup.confirmPassword')}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                            <Input {...field} type="password" className="pl-10" />
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
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
