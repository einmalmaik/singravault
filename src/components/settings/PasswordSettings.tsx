// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview OPAQUE account-password change flow.
 *
 * Authenticated password changes use the same reset authorization service as
 * forgot-password: email code, optional 2FA, then client-side OPAQUE
 * re-registration. The new account password is never sent to Supabase Auth.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff, KeyRound, Loader2, MailCheck, ShieldCheck, WandSparkles } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import { TwoFactorVerificationModal } from '@/components/auth/TwoFactorVerificationModal';
import { useToast } from '@/hooks/use-toast';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import {
    canCurrentUserUseAppPasswordFlow,
    completeOpaqueAccountPasswordReset,
    requestAccountPasswordEmailCode,
    verifyAccountPasswordEmailCode,
    verifyAccountPasswordResetSecondFactor,
} from '@/services/accountPasswordResetService';
import { clearPersistentSession } from '@/services/authSessionManager';
import { DEFAULT_PASSWORD_OPTIONS, generatePassword } from '@/services/passwordGenerator';

type PasswordChangeStep = 'idle' | 'email_code_requested' | 'new_password_allowed';

export function PasswordSettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const navigate = useNavigate();
    const passwordCheck = usePasswordCheck({ enforceStrong: true });

    const [step, setStep] = useState<PasswordChangeStep>('idle');
    const [emailCode, setEmailCode] = useState('');
    const [resetToken, setResetToken] = useState<string | null>(null);
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const [show2FAModal, setShow2FAModal] = useState(false);

    const accountEmail = user?.email ?? '';
    const canUseAppPasswordFlow = canCurrentUserUseAppPasswordFlow(user);

    const resetLocalState = () => {
        setStep('idle');
        setEmailCode('');
        setResetToken(null);
        setNewPassword('');
        setConfirmPassword('');
        passwordCheck.onPasswordChange('');
    };

    const handleRequestEmailCode = async () => {
        setIsUpdating(true);
        try {
            await requestAccountPasswordEmailCode({ purpose: 'change' });
            setStep('email_code_requested');
            toast({
                title: t('common.success'),
                description: t('settings.password.emailCodeSent'),
            });
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('settings.password.updateFailed'),
            });
        } finally {
            setIsUpdating(false);
        }
    };

    const handleVerifyEmailCode = async () => {
        if (!emailCode.trim()) return;

        setIsUpdating(true);
        try {
            const result = await verifyAccountPasswordEmailCode({
                purpose: 'change',
                code: emailCode.trim(),
            });
            setResetToken(result.resetToken);

            if (result.requires2FA) {
                setShow2FAModal(true);
                return;
            }

            setStep('new_password_allowed');
            toast({
                title: t('common.success'),
                description: t('settings.password.emailCodeVerified'),
            });
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('settings.password.codeInvalid'),
            });
        } finally {
            setIsUpdating(false);
        }
    };

    const handleVerifySecondFactor = async (code: string, isBackupCode: boolean) => {
        if (!resetToken) return false;

        try {
            await verifyAccountPasswordResetSecondFactor({
                resetToken,
                code,
                isBackupCode,
            });
            setShow2FAModal(false);
            setStep('new_password_allowed');
            toast({
                title: t('common.success'),
                description: t('settings.password.twoFactorVerified'),
            });
            return true;
        } catch {
            return false;
        }
    };

    const handleGeneratePassword = () => {
        const generatedPassword = generatePassword(DEFAULT_PASSWORD_OPTIONS);
        setNewPassword(generatedPassword);
        setConfirmPassword(generatedPassword);
        passwordCheck.onPasswordChange(generatedPassword);
        passwordCheck.onPasswordBlur(generatedPassword);

        toast({
            title: t('common.success'),
            description: t('settings.password.generateSuccess'),
        });
    };

    const handleUpdatePassword = async () => {
        if (!resetToken || step !== 'new_password_allowed') {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.password.authorizationRequired'),
            });
            return;
        }

        if (newPassword.length < 12) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.password.minLength'),
            });
            return;
        }

        if (newPassword !== confirmPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('auth.errors.passwordMismatch'),
            });
            return;
        }

        const checkResult = await passwordCheck.onPasswordSubmit(newPassword);
        if (!checkResult.isAcceptable) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: checkResult.isPwned
                    ? t('passwordStrength.pwned', { count: checkResult.pwnedCount })
                    : t('settings.password.weakPassword'),
            });
            return;
        }

        setIsUpdating(true);
        try {
            await completeOpaqueAccountPasswordReset({
                resetToken,
                newPassword,
            });

            resetLocalState();
            toast({
                title: t('common.success'),
                description: t('settings.password.updateSuccess'),
            });

            await clearPersistentSession();
            await supabase.auth.signOut().catch(() => undefined);
            navigate('/auth', { replace: true });
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('settings.password.updateFailed'),
            });
        } finally {
            setIsUpdating(false);
        }
    };

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <KeyRound className="w-5 h-5" />
                        {t('settings.password.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.password.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Label>{t('settings.account.email')}</Label>
                        <div className="flex min-h-10 items-center rounded-md border bg-muted/40 px-3 text-sm">
                            {accountEmail || t('common.authRequired')}
                        </div>
                    </div>

                    {!canUseAppPasswordFlow ? (
                        <p className="text-sm text-muted-foreground">
                            {t('settings.password.socialOnlyDescription')}
                        </p>
                    ) : (
                        <>
                            {step === 'idle' && (
                                <Button
                                    type="button"
                                    className="w-full"
                                    onClick={handleRequestEmailCode}
                                    disabled={isUpdating}
                                >
                                    {isUpdating && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    <MailCheck className="w-4 h-4 mr-2" />
                                    {t('settings.password.requestEmailCode')}
                                </Button>
                            )}

                            {step === 'email_code_requested' && (
                                <div className="space-y-3">
                                    <div className="space-y-2">
                                        <Label htmlFor="settings-password-email-code">
                                            {t('settings.password.emailCode')}
                                        </Label>
                                        <Input
                                            id="settings-password-email-code"
                                            inputMode="numeric"
                                            value={emailCode}
                                            onChange={(event) => setEmailCode(event.target.value.replace(/\D/g, '').slice(0, 8))}
                                            placeholder="12345678"
                                            className="text-center font-mono text-lg tracking-widest"
                                            maxLength={8}
                                            autoComplete="one-time-code"
                                        />
                                    </div>
                                    <div className="grid gap-2 sm:grid-cols-2">
                                        <Button
                                            type="button"
                                            variant="outline"
                                            onClick={handleRequestEmailCode}
                                            disabled={isUpdating}
                                        >
                                            {t('settings.password.resendEmailCode')}
                                        </Button>
                                        <Button
                                            type="button"
                                            onClick={handleVerifyEmailCode}
                                            disabled={isUpdating || emailCode.length !== 8}
                                        >
                                            {isUpdating && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                            <ShieldCheck className="w-4 h-4 mr-2" />
                                            {t('common.confirm')}
                                        </Button>
                                    </div>
                                </div>
                            )}

                            {step === 'new_password_allowed' && (
                                <div className="space-y-4">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        className="w-full"
                                        onClick={handleGeneratePassword}
                                    >
                                        <WandSparkles className="w-4 h-4 mr-2" />
                                        {t('settings.password.generateButton')}
                                    </Button>

                                    <div className="space-y-2">
                                        <Label htmlFor="settings-new-password">{t('settings.password.newPassword')}</Label>
                                        <div className="relative">
                                            <Input
                                                id="settings-new-password"
                                                type={showNewPassword ? 'text' : 'password'}
                                                value={newPassword}
                                                onFocus={passwordCheck.onFieldFocus}
                                                onChange={(e) => {
                                                    setNewPassword(e.target.value);
                                                    passwordCheck.onPasswordChange(e.target.value);
                                                }}
                                                onBlur={() => passwordCheck.onPasswordBlur(newPassword)}
                                                placeholder={t('settings.password.placeholder')}
                                                className="pr-10"
                                            />
                                            <Button
                                                type="button"
                                                variant="ghost"
                                                size="icon"
                                                className="absolute right-1 top-1/2 h-7 w-7 -translate-y-1/2"
                                                onClick={() => setShowNewPassword((prev) => !prev)}
                                            >
                                                {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                            </Button>
                                        </div>
                                    </div>

                                    <div className="space-y-2">
                                        <Label htmlFor="settings-confirm-password">{t('settings.password.confirmPassword')}</Label>
                                        <div className="relative">
                                            <Input
                                                id="settings-confirm-password"
                                                type={showConfirmPassword ? 'text' : 'password'}
                                                value={confirmPassword}
                                                onChange={(e) => setConfirmPassword(e.target.value)}
                                                placeholder={t('settings.password.confirmPlaceholder')}
                                                className="pr-10"
                                            />
                                            <Button
                                                type="button"
                                                variant="ghost"
                                                size="icon"
                                                className="absolute right-1 top-1/2 h-7 w-7 -translate-y-1/2"
                                                onClick={() => setShowConfirmPassword((prev) => !prev)}
                                            >
                                                {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                            </Button>
                                        </div>
                                    </div>

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

                                    <Button
                                        onClick={handleUpdatePassword}
                                        disabled={isUpdating || passwordCheck.isChecking || !newPassword || !confirmPassword}
                                    >
                                        {isUpdating && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                        {t('settings.password.updateButton')}
                                    </Button>
                                </div>
                            )}
                        </>
                    )}
                </CardContent>
            </Card>

            <TwoFactorVerificationModal
                open={show2FAModal}
                onVerify={handleVerifySecondFactor}
                onCancel={() => {
                    setShow2FAModal(false);
                    setResetToken(null);
                }}
            />
        </>
    );
}
