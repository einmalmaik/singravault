// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Master Password Setup Component
 * 
 * Displayed after first login when no encryption salt exists.
 * Guides user through setting up their master password.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Eye, EyeOff, AlertTriangle, Loader2, Wand2, Home, LogOut } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { generatePassword } from '@/services/passwordGenerator';
import { isTauriRuntime } from '@/platform/runtime';

const MASTER_PASSWORD_LENGTH = 20;
const WEAK_PARTS = ['password', 'qwerty', 'admin', 'welcome', 'letmein', 'singra'];
const SEQUENTIAL_NUMBER_PATTERN = /(01234|12345|23456|34567|45678|56789|98765|87654|76543|65432|54321)/;
const NAME_PLUS_NUMBER_PATTERN = /^[A-Za-z]{3,}\d{3,}[^A-Za-z0-9]*$/;

function hasWeakMasterPasswordPattern(password: string): boolean {
    const lower = password.toLowerCase();
    if (WEAK_PARTS.some((part) => lower.includes(part))) return true;
    if (SEQUENTIAL_NUMBER_PATTERN.test(password)) return true;
    if (NAME_PLUS_NUMBER_PATTERN.test(password)) return true;
    if (/(.)\1{4,}/.test(password)) return true;
    return false;
}

export function MasterPasswordSetup() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { toast } = useToast();
    const { setupMasterPassword } = useVault();
    const { signOut } = useAuth();

    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [signOutLoading, setSignOutLoading] = useState(false);

    const passwordCheck = usePasswordCheck({ enforceStrong: true });

    const handlePasswordChange = (value: string) => {
        setPassword(value);
        passwordCheck.onPasswordChange(value);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (password !== confirmPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('auth.errors.passwordMismatch'),
            });
            return;
        }

        // Password complexity validation (same as signup)
        if (password.length < 12) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: 'Master-Passwort muss mindestens 12 Zeichen haben.',
            });
            return;
        }

        if (!/[A-Z]/.test(password)) {
            toast({ variant: 'destructive', title: t('common.error'), description: t('auth.errors.passwordNoUppercase') });
            return;
        }

        if (!/[a-z]/.test(password)) {
            toast({ variant: 'destructive', title: t('common.error'), description: t('auth.errors.passwordNoLowercase') });
            return;
        }

        if (!/[0-9]/.test(password)) {
            toast({ variant: 'destructive', title: t('common.error'), description: t('auth.errors.passwordNoDigit') });
            return;
        }

        if (!/[^A-Za-z0-9]/.test(password)) {
            toast({ variant: 'destructive', title: t('common.error'), description: t('auth.errors.passwordNoSymbol') });
            return;
        }

        if (hasWeakMasterPasswordPattern(password)) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: 'Unsicheres Muster erkannt (z.B. 12345 oder name12345@). Bitte ein starkes Passwort nutzen.',
            });
            return;
        }

        // Full zxcvbn + HIBP check
        const checkResult = await passwordCheck.onPasswordSubmit(password);
        if (!checkResult.isAcceptable) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: checkResult.isPwned
                    ? t('passwordStrength.pwned', { count: checkResult.pwnedCount })
                    : 'Master-Passwort ist zu schwach. Bitte ein starkes Passwort verwenden.',
            });
            return;
        }

        setLoading(true);
        const { error } = await setupMasterPassword(password);
        setLoading(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error.message,
            });
        } else {
            toast({
                title: t('common.success'),
                description: 'Tresor erfolgreich eingerichtet!',
            });
        }
    };

    const handleGenerateStrongPassword = () => {
        const generated = generatePassword({
            length: MASTER_PASSWORD_LENGTH,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
        });

        setPassword(generated);
        setConfirmPassword(generated);
        passwordCheck.onPasswordChange(generated);

        toast({
            title: t('common.info'),
            description: 'Starkes Master-Passwort generiert. Bitte sicher speichern.',
        });
    };

    const handleUseDifferentAccount = async () => {
        setSignOutLoading(true);
        try {
            await signOut();
            navigate('/auth?mode=login', { replace: true });
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('auth.errors.generic'),
            });
        } finally {
            setSignOutLoading(false);
        }
    };

    const handleGoHome = () => {
        navigate('/', { replace: true });
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary/5 via-background to-primary/10 p-4">
            <Card className="w-full max-w-md shadow-xl">
                <CardHeader className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 rounded-full bg-primary/10">
                            <Shield className="w-8 h-8 text-primary" />
                        </div>
                    </div>
                    <CardTitle className="text-2xl">
                        {t('auth.masterPassword.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('auth.masterPassword.subtitle')}
                    </CardDescription>
                </CardHeader>

                <CardContent>
                    <Alert className="mb-6 border-amber-500/50 bg-amber-500/10">
                        <AlertTriangle className="h-4 w-4 text-amber-500" />
                        <AlertDescription className="text-amber-600 dark:text-amber-400">
                            {t('auth.masterPassword.warning')}
                            <br />
                            Dringend empfohlen: Nutze ein starkes Master-Passwort. Schwache Muster wie 12345 sind gesperrt.
                        </AlertDescription>
                    </Alert>

                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="master-password">
                                {t('auth.masterPassword.password')}
                            </Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                <Input
                                    id="master-password"
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => handlePasswordChange(e.target.value)}
                                    onFocus={passwordCheck.onFieldFocus}
                                    onBlur={(e) => passwordCheck.onPasswordBlur(e.target.value)}
                                    className="pl-10 pr-10"
                                    placeholder="••••••••••••"
                                    required
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="icon"
                                    className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                                    onClick={() => setShowPassword(!showPassword)}
                                >
                                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </Button>
                            </div>

                            {/* Strength indicator (zxcvbn) */}
                            {password && passwordCheck.strengthResult && (
                                <PasswordStrengthMeter
                                    score={passwordCheck.strengthResult.score}
                                    feedback={passwordCheck.strengthResult.feedback}
                                    crackTimeDisplay={passwordCheck.strengthResult.crackTimeDisplay}
                                    isPwned={passwordCheck.pwnedResult?.isPwned ?? false}
                                    pwnedCount={passwordCheck.pwnedResult?.pwnedCount ?? 0}
                                    isChecking={passwordCheck.isChecking}
                                />
                            )}

                            <Button
                                type="button"
                                variant="outline"
                                size="sm"
                                className="mt-2"
                                onClick={handleGenerateStrongPassword}
                            >
                                <Wand2 className="w-4 h-4 mr-2" />
                                Starkes Passwort generieren
                            </Button>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirm-password">
                                {t('auth.masterPassword.confirmPassword')}
                            </Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                <Input
                                    id="confirm-password"
                                    type="password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    className="pl-10"
                                    placeholder="••••••••••••"
                                    required
                                />
                            </div>
                            {confirmPassword && password !== confirmPassword && (
                                <p className="text-xs text-destructive">
                                    {t('auth.errors.passwordMismatch')}
                                </p>
                            )}
                        </div>

                        <Button
                            type="submit"
                            className="w-full"
                            disabled={loading || !password || password !== confirmPassword}
                        >
                            {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('auth.masterPassword.submit')}
                        </Button>
                    </form>

                    <div className="mt-6 border-t pt-4 space-y-2">
                        {!isTauriRuntime() && (
                            <Button
                                type="button"
                                variant="outline"
                                className="w-full"
                                onClick={handleGoHome}
                            >
                                <Home className="w-4 h-4 mr-2" />
                                Zur Startseite
                            </Button>
                        )}

                        <Button
                            type="button"
                            variant="ghost"
                            className="w-full text-muted-foreground"
                            disabled={loading || signOutLoading}
                            onClick={() => void handleUseDifferentAccount()}
                        >
                            {signOutLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {!signOutLoading && <LogOut className="w-4 h-4 mr-2" />}
                            Anderes Konto verwenden
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
