// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Reauthentication dialog for sensitive account actions.
 *
 * Prompts the user for account password and refreshes the auth session
 * before continuing dangerous operations.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2 } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import {
    getSensitiveActionReauthMethod,
    reauthenticateWithAccountPassword,
    reauthenticateWithSessionRefresh,
    type SensitiveActionReauthMethod,
} from '@/services/sensitiveActionReauthService';

export interface SensitiveActionReauthDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => Promise<boolean | void> | boolean | void;
    description?: string;
    confirmationKeyword?: string;
}

export function SensitiveActionReauthDialog({
    open,
    onOpenChange,
    onSuccess,
    description,
    confirmationKeyword,
}: SensitiveActionReauthDialogProps) {
    const { t } = useTranslation();
    const [password, setPassword] = useState('');
    const [confirmationInput, setConfirmationInput] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isResolvingMethod, setIsResolvingMethod] = useState(false);
    const [reauthMethod, setReauthMethod] = useState<SensitiveActionReauthMethod>('password');
    const [errorCode, setErrorCode] = useState<string | null>(null);
    const requiredKeyword = (confirmationKeyword || t('reauth.confirmationKeywordDefault')).trim();
    const normalizedRequiredKeyword = requiredKeyword.toUpperCase();

    useEffect(() => {
        if (open) {
            return;
        }

        setPassword('');
        setConfirmationInput('');
        setIsSubmitting(false);
        setIsResolvingMethod(false);
        setReauthMethod('password');
        setErrorCode(null);
    }, [open]);

    useEffect(() => {
        if (!open) {
            return;
        }

        let active = true;
        setIsResolvingMethod(true);

        getSensitiveActionReauthMethod()
            .then((method) => {
                if (active) {
                    setReauthMethod(method);
                }
            })
            .catch(() => {
                if (active) {
                    setReauthMethod('password');
                }
            })
            .finally(() => {
                if (active) {
                    setIsResolvingMethod(false);
                }
            });

        return () => {
            active = false;
        };
    }, [open]);

    const resolveErrorMessage = () => {
        if (errorCode === 'INVALID_CREDENTIALS') {
            return t('reauth.invalidCredentials');
        }

        if (errorCode === 'TWO_FACTOR_REQUIRED') {
            return t('reauth.twoFactorRequired');
        }

        if (errorCode === 'AUTH_REQUIRED') {
            return t('reauth.authRequired');
        }

        if (errorCode === 'CONFIRMATION_MISMATCH') {
            return t('reauth.confirmationMismatch', { keyword: requiredKeyword });
        }

        return t('reauth.failed');
    };

    const handleConfirm = async () => {
        if (isSubmitting) {
            return;
        }

        setIsSubmitting(true);
        setErrorCode(null);

        try {
            const result = reauthMethod === 'password'
                ? await reauthenticateWithAccountPassword(password)
                : await handleConfirmationReauth();

            if (!result.success) {
                setErrorCode(result.error || 'REAUTH_FAILED');
                return;
            }

            const shouldClose = await onSuccess();
            if (shouldClose !== false) {
                onOpenChange(false);
            }
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleConfirmationReauth = async () => {
        const normalizedConfirmationInput = confirmationInput.trim().toUpperCase();
        if (normalizedConfirmationInput !== normalizedRequiredKeyword) {
            return { success: false, error: 'CONFIRMATION_MISMATCH' };
        }

        return reauthenticateWithSessionRefresh();
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>{t('reauth.title')}</DialogTitle>
                    <DialogDescription>
                        {description || t('reauth.description')}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-2 py-2">
                    {isResolvingMethod && (
                        <p className="text-sm text-muted-foreground">
                            {t('common.loading')}
                        </p>
                    )}

                    {!isResolvingMethod && reauthMethod === 'password' && (
                        <>
                            <Label htmlFor="sensitive-reauth-password">{t('reauth.passwordLabel')}</Label>
                            <Input
                                id="sensitive-reauth-password"
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder={t('reauth.passwordPlaceholder')}
                                disabled={isSubmitting}
                                autoComplete="current-password"
                            />
                        </>
                    )}

                    {!isResolvingMethod && reauthMethod === 'confirmation' && (
                        <>
                            <Label htmlFor="sensitive-reauth-confirmation">
                                {t('reauth.confirmationLabel', { keyword: requiredKeyword })}
                            </Label>
                            <Input
                                id="sensitive-reauth-confirmation"
                                value={confirmationInput}
                                onChange={(e) => setConfirmationInput(e.target.value)}
                                placeholder={t('reauth.confirmationPlaceholder', { keyword: requiredKeyword })}
                                disabled={isSubmitting}
                                autoComplete="off"
                            />
                            <p className="text-xs text-muted-foreground">
                                {t('reauth.confirmationHint', { keyword: requiredKeyword })}
                            </p>
                        </>
                    )}

                    {errorCode && (
                        <p className="text-sm text-destructive">{resolveErrorMessage()}</p>
                    )}
                </div>

                <DialogFooter className="flex gap-2">
                    <Button
                        variant="outline"
                        onClick={() => onOpenChange(false)}
                        disabled={isSubmitting}
                    >
                            {t('common.cancel')}
                    </Button>
                    <Button
                        onClick={handleConfirm}
                        disabled={
                            isSubmitting
                            || isResolvingMethod
                            || (reauthMethod === 'password'
                                ? !password.trim()
                                : !confirmationInput.trim())
                        }
                    >
                        {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        {t('reauth.confirm')}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
