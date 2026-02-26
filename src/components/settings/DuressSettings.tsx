// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Duress (Panic) Password Settings Component
 *
 * Allows premium users to set up a secondary "panic" password that
 * unlocks a decoy vault instead of their real vault.
 *
 * Use case: Protection against coerced disclosure (border control,
 * threats, extortion). The decoy vault contains plausible but
 * non-sensitive items.
 *
 * Feature-gated: Premium and Families tiers only.
 */

import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
    AlertTriangle,
    Shield,
    ShieldCheck,
    ShieldOff,
    Eye,
    EyeOff,
    Loader2,
    Info,
    Trash2,
} from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';

import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import { supabase } from '@/integrations/supabase/client';
import {
    getDuressConfig,
    setupDuressPassword,
    disableDuressMode,
    changeDuressPassword,
    getDefaultDecoyItems,
    markAsDecoyItem,
    DuressConfig,
} from '@/services/duressService';
import { deriveKey, encryptVaultItem } from '@/services/cryptoService';

export function DuressSettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const navigate = useNavigate();
    const { user } = useAuth();
    const { isLocked } = useVault();
    const { allowed: hasAccess } = useFeatureGate('duress_password');

    // State
    const [duressConfig, setDuressConfig] = useState<DuressConfig | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSettingUp, setIsSettingUp] = useState(false);
    const [showSetupDialog, setShowSetupDialog] = useState(false);
    const [showDisableDialog, setShowDisableDialog] = useState(false);
    const [showChangeDialog, setShowChangeDialog] = useState(false);

    // Form state
    const [duressPassword, setDuressPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [masterPassword, setMasterPassword] = useState('');
    const [currentDuressPassword, setCurrentDuressPassword] = useState('');
    const [showDuressPassword, setShowDuressPassword] = useState(false);
    const [showMasterPassword, setShowMasterPassword] = useState(false);

    // Load duress config on mount
    useEffect(() => {
        async function loadConfig() {
            if (!user?.id) return;

            try {
                const config = await getDuressConfig(user.id);
                setDuressConfig(config);
            } catch (err) {
                console.error('Failed to load duress config:', err);
            } finally {
                setIsLoading(false);
            }
        }

        loadConfig();
    }, [user?.id]);

    // Reset form state
    const resetForm = useCallback(() => {
        setDuressPassword('');
        setConfirmPassword('');
        setMasterPassword('');
        setCurrentDuressPassword('');
        setShowDuressPassword(false);
        setShowMasterPassword(false);
    }, []);

    // Load user's encryption salt
    async function getUserSalt(): Promise<string | null> {
        if (!user?.id) return null;

        const { data } = await supabase
            .from('profiles')
            .select('encryption_salt')
            .eq('user_id', user.id)
            .single();

        return (data as { encryption_salt?: string } | null)?.encryption_salt || null;
    }

    /**
     * Enables duress mode by setting up a panic password.
     * Creates default decoy items encrypted with the duress key.
     */
    async function handleSetup() {
        if (!user?.id || !hasAccess) return;

        // Validation
        if (duressPassword.length < 8) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.passwordTooShort'),
            });
            return;
        }

        if (duressPassword !== confirmPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.passwordMismatch'),
            });
            return;
        }

        if (!masterPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.masterPasswordRequired'),
            });
            return;
        }

        setIsSettingUp(true);

        try {
            const realSalt = await getUserSalt();
            if (!realSalt) {
                throw new Error('Could not retrieve encryption salt');
            }

            const result = await setupDuressPassword(
                user.id,
                duressPassword,
                masterPassword,
                realSalt,
            );

            if (!result.success) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: result.error || t('duress.setupFailed'),
                });
                return;
            }

            // Reload config to get the new duress salt
            const config = await getDuressConfig(user.id);
            setDuressConfig(config);

            // Create default decoy items encrypted with the duress key
            if (config?.enabled && config.salt) {
                try {
                    // Derive the duress key to encrypt decoy items
                    const duressKey = await deriveKey(duressPassword, config.salt, config.kdfVersion);

                    // Get user's default vault
                    const { data: vault } = await supabase
                        .from('vaults')
                        .select('id')
                        .eq('user_id', user.id)
                        .eq('is_default', true)
                        .single();

                    if (vault) {
                        // Create default decoy items
                        const decoyItems = getDefaultDecoyItems();
                        for (const item of decoyItems) {
                            const decoyData = markAsDecoyItem({
                                title: item.title,
                                websiteUrl: item.website,
                                username: item.username,
                                password: item.password,
                                notes: item.notes,
                                itemType: 'password' as const,
                                isFavorite: false,
                                categoryId: null,
                            });

                            const encryptedData = await encryptVaultItem(decoyData, duressKey);

                            await supabase
                                .from('vault_items')
                                .insert({
                                    user_id: user.id,
                                    vault_id: vault.id,
                                    title: 'Encrypted Item',
                                    encrypted_data: encryptedData,
                                    item_type: 'password',
                                    is_favorite: false,
                                });
                        }
                    }
                } catch (decoyErr) {
                    // Non-fatal: decoy items are a convenience, not required
                    console.warn('Failed to create default decoy items:', decoyErr);
                }
            }

            toast({
                title: t('duress.setupSuccess'),
                description: t('duress.setupSuccessDescription'),
            });

            setShowSetupDialog(false);
            resetForm();
        } catch (err) {
            console.error('Duress setup error:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.setupFailed'),
            });
        } finally {
            setIsSettingUp(false);
        }
    }

    /**
     * Disables duress mode.
     */
    async function handleDisable() {
        if (!user?.id) return;

        setIsSettingUp(true);

        try {
            const result = await disableDuressMode(user.id);

            if (!result.success) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: result.error || t('duress.disableFailed'),
                });
                return;
            }

            setDuressConfig({ enabled: false, salt: null, verifier: null, kdfVersion: 2 });

            toast({
                title: t('duress.disableSuccess'),
                description: t('duress.disableSuccessDescription'),
            });

            setShowDisableDialog(false);
        } catch (err) {
            console.error('Duress disable error:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.disableFailed'),
            });
        } finally {
            setIsSettingUp(false);
        }
    }

    /**
     * Changes the duress password.
     */
    async function handleChange() {
        if (!user?.id) return;

        // Validation
        if (duressPassword.length < 8) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.passwordTooShort'),
            });
            return;
        }

        if (duressPassword !== confirmPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.passwordMismatch'),
            });
            return;
        }

        setIsSettingUp(true);

        try {
            const result = await changeDuressPassword(
                user.id,
                currentDuressPassword,
                duressPassword,
                masterPassword,
            );

            if (!result.success) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: result.error || t('duress.changeFailed'),
                });
                return;
            }

            toast({
                title: t('duress.changeSuccess'),
                description: t('duress.changeSuccessDescription'),
            });

            setShowChangeDialog(false);
            resetForm();
        } catch (err) {
            console.error('Duress password change error:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('duress.changeFailed'),
            });
        } finally {
            setIsSettingUp(false);
        }
    }

    // Loading state
    if (isLoading) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        {t('duress.title')}
                    </CardTitle>
                </CardHeader>
                <CardContent className="flex justify-center py-8">
                    <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
                </CardContent>
            </Card>
        );
    }

    // Vault must be unlocked to manage duress settings
    if (isLocked) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5" />
                        {t('duress.title')}
                    </CardTitle>
                    <CardDescription>{t('duress.description')}</CardDescription>
                </CardHeader>
                <CardContent>
                    <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{t('duress.unlockRequired')}</AlertDescription>
                    </Alert>
                </CardContent>
            </Card>
        );
    }

    const isEnabled = duressConfig?.enabled ?? false;

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        {isEnabled ? (
                            <ShieldCheck className="h-5 w-5 text-green-500" />
                        ) : (
                            <ShieldOff className="h-5 w-5 text-muted-foreground" />
                        )}
                        {t('duress.title')}
                        {isEnabled && (
                            <Badge variant="default" className="ml-2">
                                {t('duress.active')}
                            </Badge>
                        )}
                    </CardTitle>
                    <CardDescription>{t('duress.description')}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    {/* Info Alert */}
                    <Alert>
                        <Info className="h-4 w-4" />
                        <AlertTitle>{t('duress.howItWorks')}</AlertTitle>
                        <AlertDescription className="mt-2">
                            {t('duress.howItWorksDescription')}
                        </AlertDescription>
                    </Alert>

                    {/* Warning Alert */}
                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{t('duress.warning')}</AlertDescription>
                    </Alert>

                    {/* Actions */}
                    {hasAccess ? (
                        isEnabled ? (
                            <div className="flex gap-2">
                                <Button
                                    variant="outline"
                                    onClick={() => setShowChangeDialog(true)}
                                    className="flex-1"
                                >
                                    {t('duress.changePassword')}
                                </Button>
                                <Button
                                    variant="destructive"
                                    onClick={() => setShowDisableDialog(true)}
                                >
                                    <Trash2 className="h-4 w-4 mr-2" />
                                    {t('duress.disable')}
                                </Button>
                            </div>
                        ) : (
                            <Button
                                onClick={() => setShowSetupDialog(true)}
                                className="w-full"
                            >
                                <Shield className="h-4 w-4 mr-2" />
                                {t('duress.enable')}
                            </Button>
                        )
                    ) : (
                        <div className="space-y-3">
                            <Alert>
                                <AlertTriangle className="h-4 w-4" />
                                <AlertDescription>
                                    {t('duress.premiumRequired')}
                                </AlertDescription>
                            </Alert>
                            <Button
                                variant="outline"
                                onClick={() => navigate('/settings?tab=subscription')}
                                className="w-full"
                            >
                                {t('duress.upgradeNow')}
                            </Button>
                        </div>
                    )}
                </CardContent>
            </Card>

            {/* Setup Dialog */}
            <Dialog open={showSetupDialog} onOpenChange={setShowSetupDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('duress.setupTitle')}</DialogTitle>
                        <DialogDescription>{t('duress.setupDescription')}</DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4 py-4">
                        {/* Master password verification */}
                        <div className="space-y-2">
                            <Label htmlFor="masterPassword">
                                {t('duress.masterPasswordLabel')}
                            </Label>
                            <div className="relative">
                                <Input
                                    id="masterPassword"
                                    type={showMasterPassword ? 'text' : 'password'}
                                    value={masterPassword}
                                    onChange={(e) => setMasterPassword(e.target.value)}
                                    placeholder={t('duress.masterPasswordPlaceholder')}
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    className="absolute right-0 top-0 h-full px-3"
                                    onClick={() => setShowMasterPassword(!showMasterPassword)}
                                >
                                    {showMasterPassword ? (
                                        <EyeOff className="h-4 w-4" />
                                    ) : (
                                        <Eye className="h-4 w-4" />
                                    )}
                                </Button>
                            </div>
                        </div>

                        {/* Duress password */}
                        <div className="space-y-2">
                            <Label htmlFor="duressPassword">
                                {t('duress.duressPasswordLabel')}
                            </Label>
                            <div className="relative">
                                <Input
                                    id="duressPassword"
                                    type={showDuressPassword ? 'text' : 'password'}
                                    value={duressPassword}
                                    onChange={(e) => setDuressPassword(e.target.value)}
                                    placeholder={t('duress.duressPasswordPlaceholder')}
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    className="absolute right-0 top-0 h-full px-3"
                                    onClick={() => setShowDuressPassword(!showDuressPassword)}
                                >
                                    {showDuressPassword ? (
                                        <EyeOff className="h-4 w-4" />
                                    ) : (
                                        <Eye className="h-4 w-4" />
                                    )}
                                </Button>
                            </div>
                        </div>

                        {/* Confirm duress password */}
                        <div className="space-y-2">
                            <Label htmlFor="confirmPassword">
                                {t('duress.confirmPasswordLabel')}
                            </Label>
                            <Input
                                id="confirmPassword"
                                type="password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder={t('duress.confirmPasswordPlaceholder')}
                            />
                        </div>

                        <Alert>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                                {t('duress.differentPasswordWarning')}
                            </AlertDescription>
                        </Alert>
                    </div>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => {
                                setShowSetupDialog(false);
                                resetForm();
                            }}
                        >
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleSetup} disabled={isSettingUp}>
                            {isSettingUp ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    {t('duress.setting')}
                                </>
                            ) : (
                                t('duress.enable')
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Disable Confirmation Dialog */}
            <Dialog open={showDisableDialog} onOpenChange={setShowDisableDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('duress.disableTitle')}</DialogTitle>
                        <DialogDescription>{t('duress.disableDescription')}</DialogDescription>
                    </DialogHeader>

                    <Alert variant="destructive">
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>{t('duress.disableWarning')}</AlertDescription>
                    </Alert>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => setShowDisableDialog(false)}
                        >
                            {t('common.cancel')}
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDisable}
                            disabled={isSettingUp}
                        >
                            {isSettingUp ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    {t('duress.disabling')}
                                </>
                            ) : (
                                t('duress.confirmDisable')
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Change Password Dialog */}
            <Dialog open={showChangeDialog} onOpenChange={setShowChangeDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('duress.changeTitle')}</DialogTitle>
                        <DialogDescription>{t('duress.changeDescription')}</DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4 py-4">
                        {/* Current duress password */}
                        <div className="space-y-2">
                            <Label htmlFor="currentDuressPassword">
                                {t('duress.currentDuressPasswordLabel')}
                            </Label>
                            <Input
                                id="currentDuressPassword"
                                type="password"
                                value={currentDuressPassword}
                                onChange={(e) => setCurrentDuressPassword(e.target.value)}
                                placeholder={t('duress.currentDuressPasswordPlaceholder')}
                            />
                        </div>

                        {/* New duress password */}
                        <div className="space-y-2">
                            <Label htmlFor="newDuressPassword">
                                {t('duress.newDuressPasswordLabel')}
                            </Label>
                            <div className="relative">
                                <Input
                                    id="newDuressPassword"
                                    type={showDuressPassword ? 'text' : 'password'}
                                    value={duressPassword}
                                    onChange={(e) => setDuressPassword(e.target.value)}
                                    placeholder={t('duress.newDuressPasswordPlaceholder')}
                                />
                                <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    className="absolute right-0 top-0 h-full px-3"
                                    onClick={() => setShowDuressPassword(!showDuressPassword)}
                                >
                                    {showDuressPassword ? (
                                        <EyeOff className="h-4 w-4" />
                                    ) : (
                                        <Eye className="h-4 w-4" />
                                    )}
                                </Button>
                            </div>
                        </div>

                        {/* Confirm new password */}
                        <div className="space-y-2">
                            <Label htmlFor="confirmNewPassword">
                                {t('duress.confirmPasswordLabel')}
                            </Label>
                            <Input
                                id="confirmNewPassword"
                                type="password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder={t('duress.confirmPasswordPlaceholder')}
                            />
                        </div>

                        {/* Master password */}
                        <div className="space-y-2">
                            <Label htmlFor="masterPasswordChange">
                                {t('duress.masterPasswordLabel')}
                            </Label>
                            <Input
                                id="masterPasswordChange"
                                type="password"
                                value={masterPassword}
                                onChange={(e) => setMasterPassword(e.target.value)}
                                placeholder={t('duress.masterPasswordPlaceholder')}
                            />
                        </div>
                    </div>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => {
                                setShowChangeDialog(false);
                                resetForm();
                            }}
                        >
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleChange} disabled={isSettingUp}>
                            {isSettingUp ? (
                                <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    {t('duress.changing')}
                                </>
                            ) : (
                                t('duress.confirmChange')
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
}
