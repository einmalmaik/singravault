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
import { reauthenticateWithAccountPassword } from '@/services/sensitiveActionReauthService';

export interface SensitiveActionReauthDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSuccess: () => Promise<boolean | void> | boolean | void;
    description?: string;
}

export function SensitiveActionReauthDialog({
    open,
    onOpenChange,
    onSuccess,
    description,
}: SensitiveActionReauthDialogProps) {
    const { t } = useTranslation();
    const [password, setPassword] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [errorCode, setErrorCode] = useState<string | null>(null);

    useEffect(() => {
        if (open) {
            return;
        }

        setPassword('');
        setIsSubmitting(false);
        setErrorCode(null);
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

        return t('reauth.failed');
    };

    const handleConfirm = async () => {
        if (isSubmitting) {
            return;
        }

        setIsSubmitting(true);
        setErrorCode(null);

        try {
            const result = await reauthenticateWithAccountPassword(password);
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
                    <Button onClick={handleConfirm} disabled={isSubmitting || !password.trim()}>
                        {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        {t('reauth.confirm')}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
