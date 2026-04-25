// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Unlock Component
 * 
 * Displayed when the vault is locked. Prompts user to enter
 * their master password to derive the encryption key.
 * Optionally requires 2FA if vault 2FA protection is enabled.
 * Supports passkey-based unlock via WebAuthn PRF extension.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Shield, Lock, Eye, EyeOff, Loader2, LogOut, Fingerprint } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { TwoFactorVerificationModal } from '@/components/auth/TwoFactorVerificationModal';
import { verifyTwoFactorCode } from '@/services/twoFactorService';

export function VaultUnlock() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { unlock, unlockWithPasskey, pendingSessionRestore, webAuthnAvailable, hasPasskeyUnlock } = useVault();
    const { signOut, user, loading: authLoading } = useAuth();

    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [loading, setLoading] = useState(false);
    const [passkeyLoading, setPasskeyLoading] = useState(false);

    // Vault 2FA state
    const [show2FAModal, setShow2FAModal] = useState(false);
    const [pendingTwoFactor, setPendingTwoFactor] = useState<{
        resolve: (verified: boolean) => void;
    } | null>(null);

    const requestVaultTwoFactor = (): Promise<boolean> => new Promise((resolve) => {
        setPendingTwoFactor({ resolve });
        setShow2FAModal(true);
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!password || !user) return;

        await performUnlock(password);
    };

    const performUnlock = async (masterPassword: string) => {
        setLoading(true);
        const { error } = await unlock(masterPassword, {
            verifyTwoFactor: requestVaultTwoFactor,
        });
        setLoading(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error.message || t('auth.unlock.invalidMasterPassword', 'Invalid master password'),
            });
            setPassword('');
        }
    };

    const handlePasskeyUnlock = async () => {
        if (!webAuthnAvailable) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t(
                    'passkey.webAuthnUnavailable',
                    'Passkey-Entsperrung ist in diesem Browser oder für diese App-Oberfläche nicht verfügbar.',
                ),
            });
            return;
        }

        setPasskeyLoading(true);
        const { error } = await unlockWithPasskey({
            verifyTwoFactor: requestVaultTwoFactor,
        });
        setPasskeyLoading(false);

        if (error) {
            // Don't show error for user cancellation
            if (error.message.includes('cancelled')) return;

            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error.message || t('passkey.unlockFailed', 'Passkey unlock failed. Please try your master password.'),
            });
        }
    };

    const handle2FAVerify = async (code: string, isBackupCode: boolean): Promise<boolean> => {
        if (!user || !pendingTwoFactor) return false;

        try {
            const result = await verifyTwoFactorCode({
                userId: user.id,
                context: 'vault_unlock',
                code,
                method: isBackupCode ? 'backup_code' : 'totp',
            });

            if (result.success) {
                setShow2FAModal(false);
                pendingTwoFactor.resolve(true);
                setPendingTwoFactor(null);
                return true;
            }
            return false;
        } catch (err) {
            console.error('2FA verification error:', err);
            return false;
        }
    };

    const handle2FACancel = () => {
        setShow2FAModal(false);
        pendingTwoFactor?.resolve(false);
        setPendingTwoFactor(null);
        setPassword('');
    };

    const handleLogout = async () => {
        await signOut();
    };

    const showPasskeyOption = hasPasskeyUnlock;

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
                        {t('auth.unlock.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('auth.unlock.subtitle')}
                    </CardDescription>
                    {pendingSessionRestore && (
                        <div className="mt-3 px-3 py-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm text-blue-600 dark:text-blue-400">
                            {t('auth.unlock.sessionRestore', 'Please re-enter your master password to continue your session.')}
                        </div>
                    )}
                </CardHeader>

                <CardContent className="space-y-4">
                    {/* Passkey unlock button (shown first if available) */}
                    {showPasskeyOption && (
                        <>
                            <Button
                                type="button"
                                variant="outline"
                                className="w-full h-12 text-base gap-3 border-primary/30 hover:bg-primary/5"
                                onClick={handlePasskeyUnlock}
                                disabled={passkeyLoading || loading || authLoading}
                            >
                                {passkeyLoading || authLoading ? (
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                ) : (
                                    <Fingerprint className="w-5 h-5" />
                                )}
                                {t('passkey.unlockWithPasskey', 'Unlock with Passkey')}
                            </Button>

                            <div className="relative">
                                <Separator />
                                <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card px-3 text-xs text-muted-foreground">
                                    {t('common.or', 'or')}
                                </span>
                            </div>
                        </>
                    )}

                    {/* Master password form */}
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div className="space-y-2">
                            <Label htmlFor="unlock-password">
                                {t('auth.unlock.password')}
                            </Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                <Input
                                    id="unlock-password"
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="pl-10 pr-10"
                                    placeholder="••••••••••••"
                                    autoFocus={!showPasskeyOption}
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
                        </div>

                        <Button
                            type="submit"
                            className="w-full"
                            disabled={loading || passkeyLoading || !password}
                        >
                            {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('auth.unlock.submit')}
                        </Button>

                        <div className="pt-4 border-t">
                            <Button
                                type="button"
                                variant="ghost"
                                className="w-full text-muted-foreground"
                                onClick={handleLogout}
                            >
                                <LogOut className="w-4 h-4 mr-2" />
                                {t('auth.unlock.logout')}
                            </Button>
                        </div>
                    </form>
                </CardContent>
            </Card>

            {/* Two-Factor Verification Modal for Vault */}
            <TwoFactorVerificationModal
                open={show2FAModal}
                onVerify={handle2FAVerify}
                onCancel={handle2FACancel}
            />
        </div>
    );
}
