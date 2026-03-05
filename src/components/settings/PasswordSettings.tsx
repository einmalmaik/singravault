// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 â€” see LICENSE
/**
 * @fileoverview Password Settings Component
 *
 * Allows authenticated users to change their account password directly
 * from the account settings page.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeOff, KeyRound, Loader2 } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

export function PasswordSettings() {
    const { t } = useTranslation();
    const { toast } = useToast();

    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [showNewPassword, setShowNewPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);

    const handleUpdatePassword = async () => {
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

        setIsUpdating(true);
        const { error } = await supabase.auth.updateUser({ password: newPassword });
        setIsUpdating(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.password.updateFailed'),
            });
            return;
        }

        setNewPassword('');
        setConfirmPassword('');
        toast({
            title: t('common.success'),
            description: t('settings.password.updateSuccess'),
        });
    };

    return (
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
                    <Label htmlFor="settings-new-password">{t('settings.password.newPassword')}</Label>
                    <div className="relative">
                        <Input
                            id="settings-new-password"
                            type={showNewPassword ? 'text' : 'password'}
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢"
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
                            placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢"
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

                <Button
                    onClick={handleUpdatePassword}
                    disabled={isUpdating || !newPassword || !confirmPassword}
                >
                    {isUpdating && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                    {t('settings.password.updateButton')}
                </Button>
            </CardContent>
        </Card>
    );
}
