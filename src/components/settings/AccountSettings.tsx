// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Account Settings Component
 * 
 * Displays account information and actions (logout, delete account)
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { User, LogOut, Trash2, Loader2, Mail, Download, ShieldCheck, AlertTriangle, Languages } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    AlertDialog,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { SensitiveActionReauthDialog } from '@/components/security/SensitiveActionReauthDialog';

import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { deleteDeviceKey } from '@/services/deviceKeyService';
import { clearIntegrityBaseline } from '@/services/vaultIntegrityService';
import { isSensitiveActionSessionFresh } from '@/services/sensitiveActionReauthService';
import { clearOfflineVaultData } from '@/services/offlineVaultService';
import { saveExportFile } from '@/services/exportFileService';
import { buildVaultExportPayload } from '@/services/vaultExportService';
import { verifyTwoFactorChallenge } from '@/services/twoFactorService';
import { clearLastOAuthProvider } from '@/services/socialLoginPreferenceService';
import { invokeAuthedFunction, isEdgeFunctionServiceError } from '@/services/edgeFunctionService';
import {
    changeLanguagePreference,
    getStoredLanguagePreference,
    isLanguagePreference,
    languages,
    resolveSystemLanguage,
    SYSTEM_LANGUAGE_PREFERENCE,
    type LanguageCode,
    type LanguagePreference,
} from '@/i18n';

const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';

export function AccountSettings() {
    const { t } = useTranslation();
    const { user, signOut } = useAuth();
    const { decryptItem, isLocked } = useVault();
    const { toast } = useToast();
    const navigate = useNavigate();

    const [showDeleteDialog, setShowDeleteDialog] = useState(false);
    const [showReauthDialog, setShowReauthDialog] = useState(false);
    const [deleteConfirmation, setDeleteConfirmation] = useState('');
    const [twoFactorCode, setTwoFactorCode] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);
    const [isExporting, setIsExporting] = useState(false);
    const [isLoadingDeleteContext, setIsLoadingDeleteContext] = useState(false);
    const [vaultItemCount, setVaultItemCount] = useState(0);
    const [accountTwoFactorEnabled, setAccountTwoFactorEnabled] = useState(false);
    const [languagePreference, setLanguagePreference] = useState<LanguagePreference>(() => getStoredLanguagePreference());

    const systemLanguage = resolveSystemLanguage();
    const supportedLanguages = Object.entries(languages) as Array<[LanguageCode, (typeof languages)[LanguageCode]]>;

    useEffect(() => {
        if (!showDeleteDialog || !user) {
            return;
        }

        let active = true;
        setIsLoadingDeleteContext(true);

        Promise.all([
            supabase
                .from('vault_items')
                .select('id', { count: 'exact', head: true })
                .eq('user_id', user.id),
            supabase
                .from('user_2fa')
                .select('is_enabled')
                .eq('user_id', user.id)
                .maybeSingle(),
        ])
            .then(([itemsResult, twoFactorResult]) => {
                if (!active) return;
                setVaultItemCount(itemsResult.count ?? 0);
                setAccountTwoFactorEnabled(Boolean(twoFactorResult.data?.is_enabled));
            })
            .catch(() => {
                if (!active) return;
                setVaultItemCount(0);
                setAccountTwoFactorEnabled(true);
            })
            .finally(() => {
                if (active) {
                    setIsLoadingDeleteContext(false);
                }
            });

        return () => {
            active = false;
        };
    }, [showDeleteDialog, user]);

    const handleLogout = async () => {
        await signOut();
        navigate('/');
    };

    const handleLanguagePreferenceChange = (value: string) => {
        if (!isLanguagePreference(value)) {
            return;
        }

        setLanguagePreference(value);
        changeLanguagePreference(value);
    };

    const executeDeleteAccount = async (): Promise<boolean> => {
        setIsDeleting(true);
        try {
            if (!user) {
                throw new Error('No authenticated user');
            }

            let twoFactorChallengeId: string | null = null;
            if (accountTwoFactorEnabled) {
                const verification = await verifyTwoFactorChallenge({
                    context: 'critical_action',
                    code: twoFactorCode,
                    method: 'totp',
                });
                if (!verification.success || !verification.challengeId) {
                    toast({
                        variant: 'destructive',
                        title: t('common.error'),
                        description: t('settings.account.deleteTwoFactorInvalid'),
                    });
                    return false;
                }
                twoFactorChallengeId = verification.challengeId;
            }

            const data = await invokeAuthedFunction<{ deleted?: boolean }>('account-delete', {
                twoFactorChallengeId,
            });
            if (!data || data.deleted !== true) {
                throw new Error('Account deletion verification failed');
            }

            // Clear local client artifacts tied to the deleted account.
            localStorage.removeItem(`singra_verify_${user.id}`);
            await Promise.allSettled([
                clearOfflineVaultData(user.id),
                clearIntegrityBaseline(user.id),
                deleteDeviceKey(user.id),
            ]);
            clearLastOAuthProvider();

            // Best effort sign-out after account deletion.
            await signOut().catch(() => undefined);

            toast({
                title: t('settings.account.deleteSuccess'),
                description: t('settings.account.deleteSuccessDesc'),
            });

            navigate('/');
            return true;
        } catch (error) {
            if (isAccountDeleteReauthRequired(error)) {
                toast({
                    title: t('common.error'),
                    description: t('reauth.accountDeleteContext'),
                });
                setShowReauthDialog(true);
                return false;
            }

            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.account.deleteFailed'),
            });
            return false;
        } finally {
            setIsDeleting(false);
            setShowDeleteDialog(false);
            setDeleteConfirmation('');
            setTwoFactorCode('');
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

    const handleExportBeforeDelete = async () => {
        if (!user || isLocked) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.data.unlockRequired'),
            });
            return;
        }

        setIsExporting(true);
        try {
            const { data: items, error } = await supabase
                .from('vault_items')
                .select('*')
                .eq('user_id', user.id);

            if (error || !items) {
                throw error ?? new Error('Failed to fetch items');
            }

            const exportData = await buildVaultExportPayload(
                items.map((item) => ({
                    ...item,
                    title: item.title || ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                    item_type: item.item_type || 'password',
                    encrypted_data: item.encrypted_data || '',
                })),
                decryptItem,
            );

            const saved = await saveExportFile({
                name: `singra-vault-export-before-delete-${new Date().toISOString().split('T')[0]}.json`,
                mime: 'application/json',
                content: JSON.stringify(exportData, null, 2),
            });

            if (saved) {
                toast({
                    title: t('common.success'),
                    description: t('settings.data.exportSuccess', { count: exportData.itemCount }),
                });
            }
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.data.exportFailed'),
            });
        } finally {
            setIsExporting(false);
        }
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

            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Languages className="w-5 h-5" />
                        {t('settings.account.language.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.account.language.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                    <Label htmlFor="account-language">
                        {t('settings.account.language.label')}
                    </Label>
                    <Select
                        value={languagePreference}
                        onValueChange={handleLanguagePreferenceChange}
                    >
                        <SelectTrigger id="account-language">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value={SYSTEM_LANGUAGE_PREFERENCE}>
                                {t('settings.account.language.system', {
                                    language: languages[systemLanguage].name,
                                })}
                            </SelectItem>
                            {supportedLanguages.map(([code, language]) => (
                                <SelectItem key={code} value={code}>
                                    {language.name}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                        {t('settings.account.language.consentHint')}
                    </p>
                </CardContent>
            </Card>

            {/* Delete Account Confirmation Dialog */}
            <AlertDialog open={showDeleteDialog} onOpenChange={setShowDeleteDialog}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle className="text-destructive">
                            {t('settings.account.deleteConfirmTitle')}
                        </AlertDialogTitle>
                        <AlertDialogDescription asChild>
                            <div className="space-y-4 text-sm text-muted-foreground">
                                <p>{t('settings.account.deleteConfirmDesc')}</p>
                                {isLoadingDeleteContext && (
                                    <p>{t('common.loading')}</p>
                                )}
                                {vaultItemCount > 0 && (
                                    <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-destructive">
                                        <div className="flex items-start gap-2">
                                            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                                            <div className="space-y-2">
                                                <p className="font-medium">
                                                    {t('settings.account.deleteVaultWarningTitle', { count: vaultItemCount })}
                                                </p>
                                                <p>{t('settings.account.deleteVaultWarningDesc')}</p>
                                                <Button
                                                    type="button"
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={handleExportBeforeDelete}
                                                    disabled={isExporting || isLocked}
                                                    className="gap-2"
                                                >
                                                    {isExporting ? (
                                                        <Loader2 className="h-4 w-4 animate-spin" />
                                                    ) : (
                                                        <Download className="h-4 w-4" />
                                                    )}
                                                    {t('settings.account.exportBeforeDelete')}
                                                </Button>
                                            </div>
                                        </div>
                                    </div>
                                )}
                                {accountTwoFactorEnabled && (
                                    <div className="space-y-2">
                                        <Label className="flex items-center gap-2">
                                            <ShieldCheck className="h-4 w-4" />
                                            {t('settings.account.deleteTwoFactorLabel')}
                                        </Label>
                                        <Input
                                            value={twoFactorCode}
                                            onChange={(e) => setTwoFactorCode(e.target.value)}
                                            placeholder={t('settings.account.deleteTotpPlaceholder')}
                                            autoComplete="one-time-code"
                                        />
                                        <p className="text-xs text-muted-foreground">
                                            {t('settings.account.deleteTotpOnlyHint')}
                                        </p>
                                    </div>
                                )}
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
                            </div>
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel onClick={() => setDeleteConfirmation('')}>
                            {t('common.cancel')}
                        </AlertDialogCancel>
                        <Button
                            type="button"
                            onClick={handleDeleteAccount}
                            disabled={
                                deleteConfirmation.trim().toUpperCase() !== 'DELETE'
                                || isDeleting
                                || isLoadingDeleteContext
                                || (accountTwoFactorEnabled && !twoFactorCode.trim())
                            }
                            className="bg-destructive hover:bg-destructive/90"
                        >
                            {isDeleting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('settings.account.deleteConfirm')}
                        </Button>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            <SensitiveActionReauthDialog
                open={showReauthDialog}
                onOpenChange={setShowReauthDialog}
                description={t('reauth.accountDeleteContext')}
                confirmationKeyword="DELETE"
                onSuccess={executeDeleteAccount}
            />
        </>
    );
}

function isAccountDeleteReauthRequired(error: unknown): boolean {
    if (error instanceof Error && error.message.includes('REAUTH_REQUIRED')) {
        return true;
    }

    if (!isEdgeFunctionServiceError(error)) {
        return false;
    }

    return Object.values(error.details ?? {}).some((value) =>
        typeof value === 'string' && value.includes('REAUTH_REQUIRED')
    );
}
