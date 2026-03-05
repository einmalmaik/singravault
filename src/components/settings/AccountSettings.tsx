// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Account Settings Component
 * 
 * Displays account information and actions (logout, delete account)
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { User, LogOut, Trash2, Loader2, Mail } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { SensitiveActionReauthDialog } from '@/components/security/SensitiveActionReauthDialog';

import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { isSensitiveActionSessionFresh } from '@/services/sensitiveActionReauthService';

export function AccountSettings() {
    const { t } = useTranslation();
    const { user, signOut } = useAuth();
    const { toast } = useToast();
    const navigate = useNavigate();

    const [showDeleteDialog, setShowDeleteDialog] = useState(false);
    const [showReauthDialog, setShowReauthDialog] = useState(false);
    const [deleteConfirmation, setDeleteConfirmation] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);

    const handleLogout = async () => {
        await signOut();
        navigate('/');
    };

    const executeDeleteAccount = async (): Promise<boolean> => {
        setIsDeleting(true);
        try {
            if (!user) {
                throw new Error('No authenticated user');
            }

            // Delete auth user server-side. Related app data is removed via ON DELETE CASCADE.
            const { data, error: deleteError } = await supabase.rpc('delete_my_account');
            if (deleteError) {
                if (typeof deleteError.message === 'string' && deleteError.message.includes('REAUTH_REQUIRED')) {
                    toast({
                        title: t('common.error'),
                        description: t('reauth.accountDeleteContext'),
                    });
                    setShowReauthDialog(true);
                    return false;
                }
                throw deleteError;
            }
            if (!data || typeof data !== 'object' || !('deleted' in data) || data.deleted !== true) {
                throw new Error('Account deletion verification failed');
            }

            // Clear local client artifacts tied to the deleted account.
            localStorage.removeItem(`singra_verify_${user.id}`);

            // Best effort sign-out after account deletion.
            await signOut().catch(() => undefined);

            toast({
                title: t('settings.account.deleteSuccess'),
                description: t('settings.account.deleteSuccessDesc'),
            });

            navigate('/');
            return true;
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.account.deleteFailed'),
            });
            return true;
        } finally {
            setIsDeleting(false);
            setShowDeleteDialog(false);
            setDeleteConfirmation('');
        }
    };

    const handleDeleteAccount = async () => {
        if (deleteConfirmation.trim().toUpperCase() !== 'DELETE' || isDeleting) return;

        const hasFreshSession = await isSensitiveActionSessionFresh(300);
        if (!hasFreshSession) {
            setShowDeleteDialog(false);
            setShowReauthDialog(true);
            return;
        }

        await executeDeleteAccount();
    };

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <User className="w-5 h-5" />
                        {t('settings.account.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.account.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    {/* Email Display */}
                    <div className="space-y-2">
                        <Label className="flex items-center gap-2">
                            <Mail className="w-4 h-4" />
                            {t('settings.account.email')}
                        </Label>
                        <Input
                            value={user?.email || ''}
                            disabled
                            className="bg-muted"
                        />
                    </div>

                    {/* Actions */}
                    <div className="flex flex-col sm:flex-row gap-3">
                        <Button
                            variant="outline"
                            onClick={handleLogout}
                            className="flex items-center gap-2"
                        >
                            <LogOut className="w-4 h-4" />
                            {t('settings.account.logout')}
                        </Button>

                        <Button
                            variant="destructive"
                            onClick={() => setShowDeleteDialog(true)}
                            className="flex items-center gap-2"
                        >
                            <Trash2 className="w-4 h-4" />
                            {t('settings.account.deleteAccount')}
                        </Button>
                    </div>
                </CardContent>
            </Card>

            {/* Delete Account Confirmation Dialog */}
            <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle className="text-destructive">
                            {t('settings.account.deleteConfirmTitle')}
                        </AlertDialogTitle>
                        <AlertDialogDescription className="space-y-4">
                            <p>{t('settings.account.deleteConfirmDesc')}</p>
                            <div className="space-y-2">
                                <Label>
                                    {t('settings.account.deleteConfirmInput')}
                                </Label>
                                <Input
                                    value={deleteConfirmation}
                                    onChange={(e) => setDeleteConfirmation(e.target.value)}
                                    placeholder="DELETE"
                                />
                            </div>
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel onClick={() => setDeleteConfirmation('')}>
                            {t('common.cancel')}
                        </AlertDialogCancel>
                        <AlertDialogAction
                            onClick={handleDeleteAccount}
                            disabled={deleteConfirmation.trim().toUpperCase() !== 'DELETE' || isDeleting}
                            className="bg-destructive hover:bg-destructive/90"
                        >
                            {isDeleting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('settings.account.deleteConfirm')}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            <SensitiveActionReauthDialog
                open={showReauthDialog}
                onOpenChange={setShowReauthDialog}
                description={t('reauth.accountDeleteContext')}
                onSuccess={executeDeleteAccount}
            />
        </>
    );
}
