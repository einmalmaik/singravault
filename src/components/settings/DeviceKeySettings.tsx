// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Device Key Settings Component
 *
 * Allows users to enable Device Key protection, export their
 * device key for transfer to other devices, and import a device
 * key from another device.
 */

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AlertTriangle, Copy, Download, Eye, EyeOff, KeyRound, QrCode, Shield, ShieldOff, Upload } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from '@/components/ui/dialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { isTauriRuntime } from '@/platform/runtime';
import { saveExportFile } from '@/services/exportFileService';
import {
    DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH,
    exportDeviceKeyForTransfer,
    generateDeviceKeyTransferSecret,
    importDeviceKeyFromTransfer,
} from '@/services/deviceKeyService';
import { DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD } from '@/services/deviceKeyDeactivationPolicy';
import { getTwoFactorRequirement } from '@/services/twoFactorService';

export function DeviceKeySettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { deviceKeyActive, enableDeviceKey, disableDeviceKey, isLocked, refreshDeviceKeyState } = useVault();
    const { user } = useAuth();

    const [showEnableDialog, setShowEnableDialog] = useState(false);
    const [showExportDialog, setShowExportDialog] = useState(false);
    const [showImportDialog, setShowImportDialog] = useState(false);
    const [showDisableDialog, setShowDisableDialog] = useState(false);
    const [masterPassword, setMasterPassword] = useState('');
    const [disableMasterPassword, setDisableMasterPassword] = useState('');
    const [disableTwoFactorCode, setDisableTwoFactorCode] = useState('');
    const [disableVaultTwoFactorState, setDisableVaultTwoFactorState] = useState<'idle' | 'loading' | 'required' | 'not_required' | 'unavailable'>('idle');
    const [disablePhrase, setDisablePhrase] = useState('');
    const [disableAcknowledged, setDisableAcknowledged] = useState(false);
    const [pin, setPin] = useState('');
    const [exportedData, setExportedData] = useState('');
    const [importData, setImportData] = useState('');
    const [loading, setLoading] = useState(false);
    const [backupAcknowledged, setBackupAcknowledged] = useState(false);
    const [showTransferSecret, setShowTransferSecret] = useState(false);
    const isDesktopRuntime = isTauriRuntime();
    const disableConfirmationPhrase = DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD;
    const disableVaultTwoFactorRequired = disableVaultTwoFactorState === 'required';

    useEffect(() => {
        if (!showDisableDialog || !user) {
            setDisableVaultTwoFactorState('idle');
            return;
        }

        let cancelled = false;
        setDisableVaultTwoFactorState('loading');
        void getTwoFactorRequirement({ userId: user.id, context: 'vault_unlock' })
            .then((requirement) => {
                if (cancelled) return;
                setDisableVaultTwoFactorState(
                    requirement.status === 'unavailable'
                        ? 'unavailable'
                        : requirement.required ? 'required' : 'not_required',
                );
            })
            .catch(() => {
                if (!cancelled) {
                    setDisableVaultTwoFactorState('unavailable');
                }
            });

        return () => {
            cancelled = true;
        };
    }, [showDisableDialog, user]);

    const handleEnable = async () => {
        if (!masterPassword) return;
        setLoading(true);

        const { error } = await enableDeviceKey(masterPassword);

        setLoading(false);
        setShowEnableDialog(false);
        setMasterPassword('');
        setBackupAcknowledged(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.enableFailed'),
            });
        } else {
            setPin(generateDeviceKeyTransferSecret());
            setShowExportDialog(true);
            toast({
                title: t('common.success'),
                description: t('deviceKey.enableSuccess'),
            });
        }
    };

    const handleExport = async () => {
        if (!user || !pin || pin.length < DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH) return;
        setLoading(true);

        const data = await exportDeviceKeyForTransfer(user.id, pin);

        setLoading(false);
        if (data) {
            setExportedData(data);
            await supabase
                .from('profiles')
                .update({ device_key_backup_acknowledged_at: new Date().toISOString() } as Record<string, unknown>)
                .eq('user_id', user.id);
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.exportFailed'),
            });
        }
    };

    const handleImport = async () => {
        if (!user || !importData || pin.length < DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH) return;
        setLoading(true);

        let success = false;
        try {
            success = await importDeviceKeyFromTransfer(user.id, importData, pin);
        } catch {
            success = false;
        }

        setLoading(false);
        setShowImportDialog(false);
        setImportData('');
        setPin('');

        if (success) {
            toast({
                title: t('common.success'),
                description: t('deviceKey.importSuccess'),
            });
            await refreshDeviceKeyState();
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.importFailed'),
            });
        }
    };

    const handleImportFile = async (file: File | undefined) => {
        if (!file) return;
        const text = await file.text();
        setImportData(text.trim());
    };

    const handleDisable = async () => {
        if (!disableMasterPassword || disablePhrase !== disableConfirmationPhrase || !disableAcknowledged) return;
        setLoading(true);

        const { error } = await disableDeviceKey(
            disableMasterPassword,
            disableVaultTwoFactorRequired ? disableTwoFactorCode : undefined,
            disablePhrase,
        );

        setLoading(false);
        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.disableFailed'),
            });
            return;
        }

        setShowDisableDialog(false);
        setDisableMasterPassword('');
        setDisableTwoFactorCode('');
        setDisablePhrase('');
        setDisableAcknowledged(false);
        toast({
            title: t('common.success'),
            description: t('deviceKey.disableSuccess'),
        });
    };

    const copyTransferSecret = async () => {
        if (!pin) return;
        await navigator.clipboard.writeText(pin);
        toast({
            title: t('common.success'),
            description: t('deviceKey.secretCopied', 'Transfer secret copied.'),
        });
    };

    const copyExportedData = async () => {
        if (!exportedData) return;
        await navigator.clipboard.writeText(exportedData);
        toast({
            title: t('common.success'),
            description: t('deviceKey.exportCopied', 'Device Key transfer data copied.'),
        });
    };

    const downloadTransferFile = async () => {
        if (!exportedData) return;
        try {
            await saveExportFile({
                name: 'singra-device-key.singra-device-key',
                mime: 'text/plain;charset=utf-8',
                content: `${exportedData}\n`,
            });
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.exportFailed'),
            });
        }
    };

    const downloadTransferSecret = async () => {
        if (!pin) return;
        try {
            await saveExportFile({
                name: 'singra-device-key-transfer-secret.txt',
                mime: 'text/plain;charset=utf-8',
                content: `${pin}\n`,
            });
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.exportFailed'),
            });
        }
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <KeyRound className="w-5 h-5" />
                    {t('deviceKey.title')}
                </CardTitle>
                <CardDescription>
                    {t('deviceKey.description')}
                </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                {deviceKeyActive ? (
                    <>
                        <Alert>
                            <Shield className="w-4 h-4" />
                            <AlertDescription>
                                {t('deviceKey.active')}
                            </AlertDescription>
                        </Alert>

                        <div className="flex flex-col sm:flex-row gap-2">
                            <Button
                                variant="outline"
                                onClick={() => setShowExportDialog(true)}
                                disabled={isLocked}
                                className="gap-2"
                            >
                                <QrCode className="w-4 h-4" />
                                {t('deviceKey.export')}
                            </Button>
                            <Button
                                variant="destructive"
                                onClick={() => setShowDisableDialog(true)}
                                disabled={isLocked}
                                className="gap-2"
                            >
                                <ShieldOff className="w-4 h-4" />
                                {t('deviceKey.disable')}
                            </Button>
                        </div>
                    </>
                ) : (
                    <>
                        <Alert>
                            <AlertTriangle className="w-4 h-4" />
                            <AlertDescription>
                                {t('deviceKey.inactive')}
                            </AlertDescription>
                        </Alert>

                        <div className="flex flex-col sm:flex-row gap-2">
                            <Button
                                onClick={() => setShowEnableDialog(true)}
                                disabled={isLocked}
                                className="gap-2"
                            >
                                <KeyRound className="w-4 h-4" />
                                {t('deviceKey.enable')}
                            </Button>

                            <Button
                                variant="outline"
                                onClick={() => setShowImportDialog(true)}
                                className="gap-2"
                            >
                                <Upload className="w-4 h-4" />
                                {t('deviceKey.import')}
                            </Button>
                        </div>
                    </>
                )}
            </CardContent>

            {/* Enable Dialog */}
            <Dialog open={showEnableDialog} onOpenChange={setShowEnableDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.enableTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.enableDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    <Alert variant="destructive">
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                            {t('deviceKey.enableWarning')}
                        </AlertDescription>
                    </Alert>
                    <Alert>
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                            {isDesktopRuntime ? t('deviceKey.desktopBoundary') : t('deviceKey.webBoundary')}
                        </AlertDescription>
                    </Alert>
                    <div className="space-y-2">
                        <Label>{t('auth.unlock.password')}</Label>
                        <Input
                            type="password"
                            value={masterPassword}
                            onChange={(e) => setMasterPassword(e.target.value)}
                            placeholder="••••••••••••"
                        />
                    </div>
                    <div className="flex items-start gap-2">
                        <Checkbox
                            id="device-key-backup-ack"
                            checked={backupAcknowledged}
                            onCheckedChange={(checked) => setBackupAcknowledged(checked === true)}
                        />
                        <Label htmlFor="device-key-backup-ack" className="text-sm font-normal leading-snug">
                            {t('deviceKey.backupAck')}
                        </Label>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => { setShowEnableDialog(false); setBackupAcknowledged(false); }}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleEnable} disabled={!masterPassword || !backupAcknowledged || loading}>
                            {t('deviceKey.enable')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Disable Dialog */}
            <Dialog open={showDisableDialog} onOpenChange={(open) => {
                setShowDisableDialog(open);
                if (!open) {
                    setDisableMasterPassword('');
                    setDisableTwoFactorCode('');
                    setDisablePhrase('');
                    setDisableAcknowledged(false);
                    setDisableVaultTwoFactorState('idle');
                }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.disableTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.disableDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    <Alert variant="destructive">
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                            {t('deviceKey.disableWarning')}
                        </AlertDescription>
                    </Alert>
                    <div className="space-y-2">
                        <Label>{t('auth.unlock.password')}</Label>
                        <Input
                            type="password"
                            value={disableMasterPassword}
                            onChange={(e) => setDisableMasterPassword(e.target.value)}
                            placeholder="••••••••••••"
                        />
                    </div>
                    {disableVaultTwoFactorState === 'loading' && (
                        <p className="text-sm text-muted-foreground">
                            {t('deviceKey.disableTwoFactorChecking')}
                        </p>
                    )}
                    {disableVaultTwoFactorState === 'unavailable' && (
                        <Alert variant="destructive">
                            <AlertTriangle className="w-4 h-4" />
                            <AlertDescription>
                                {t('deviceKey.disableTwoFactorUnavailable')}
                            </AlertDescription>
                        </Alert>
                    )}
                    {disableVaultTwoFactorRequired && (
                        <div className="space-y-2">
                            <Label>{t('deviceKey.disableTwoFactorCode')}</Label>
                            <Input
                                inputMode="numeric"
                                autoComplete="one-time-code"
                                value={disableTwoFactorCode}
                                onChange={(e) => setDisableTwoFactorCode(e.target.value)}
                                placeholder={t('deviceKey.disableTwoFactorPlaceholder')}
                            />
                            <p className="text-xs text-muted-foreground">
                                {t('deviceKey.disableTwoFactorHelp')}
                            </p>
                        </div>
                    )}
                    <div className="space-y-2">
                        <Label>{t('deviceKey.disableConfirmLabel', { phrase: disableConfirmationPhrase })}</Label>
                        <Input
                            value={disablePhrase}
                            onChange={(e) => setDisablePhrase(e.target.value)}
                            placeholder={disableConfirmationPhrase}
                        />
                        <p className="text-xs text-muted-foreground">
                            {t('deviceKey.disableConfirmHelp')}
                        </p>
                    </div>
                    <div className="flex items-start gap-2">
                        <Checkbox
                            id="device-key-disable-ack"
                            checked={disableAcknowledged}
                            onCheckedChange={(checked) => setDisableAcknowledged(checked === true)}
                        />
                        <Label htmlFor="device-key-disable-ack" className="text-sm font-normal leading-snug">
                            {t('deviceKey.disableAck')}
                        </Label>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setShowDisableDialog(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDisable}
                            disabled={
                                !disableMasterPassword
                                || disablePhrase !== disableConfirmationPhrase
                                || disableVaultTwoFactorState === 'loading'
                                || disableVaultTwoFactorState === 'unavailable'
                                || (disableVaultTwoFactorRequired && !disableTwoFactorCode.trim())
                                || !disableAcknowledged
                                || loading
                            }
                        >
                            {t('deviceKey.disable')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Export Dialog */}
            <Dialog open={showExportDialog} onOpenChange={(open) => {
                setShowExportDialog(open);
                if (!open) { setExportedData(''); setPin(''); setShowTransferSecret(false); }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.exportTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.exportDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    <Alert>
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                            {t('deviceKey.transferWarning')}
                        </AlertDescription>
                    </Alert>
                    {!exportedData ? (
                        <>
                            <div className="space-y-2">
                                <Label>{t('deviceKey.transferPin')}</Label>
                                <div className="flex gap-2">
                                    <Input
                                        type={showTransferSecret ? 'text' : 'password'}
                                        value={pin}
                                        onChange={(e) => setPin(e.target.value)}
                                        placeholder={t('deviceKey.pinPlaceholder')}
                                        minLength={DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH}
                                    />
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="icon"
                                        onClick={() => setShowTransferSecret((value) => !value)}
                                        aria-label={showTransferSecret ? t('common.hide', 'Hide') : t('common.show', 'Show')}
                                    >
                                        {showTransferSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                    </Button>
                                    <Button
                                        type="button"
                                        variant="outline"
                                        onClick={() => setPin(generateDeviceKeyTransferSecret())}
                                    >
                                        {t('deviceKey.generateSecret')}
                                    </Button>
                                </div>
                                {pin && (
                                    <div className="flex flex-wrap gap-2">
                                        <Button type="button" variant="outline" size="sm" onClick={copyTransferSecret}>
                                            <Copy className="w-4 h-4 mr-2" />
                                            {t('common.copy', 'Copy')}
                                        </Button>
                                        <Button type="button" variant="outline" size="sm" onClick={downloadTransferSecret}>
                                            <Download className="w-4 h-4 mr-2" />
                                            {t('deviceKey.downloadSecret', 'Download secret')}
                                        </Button>
                                    </div>
                                )}
                            </div>
                            <DialogFooter>
                                <Button variant="outline" onClick={() => setShowExportDialog(false)}>
                                    {t('common.cancel')}
                                </Button>
                                <Button onClick={handleExport} disabled={pin.length < DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH || loading}>
                                    {t('deviceKey.generateCode')}
                                </Button>
                            </DialogFooter>
                        </>
                    ) : (
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <Label>{t('deviceKey.transferCode')}</Label>
                                <Textarea
                                    readOnly
                                    value={exportedData}
                                    className="min-h-32 font-mono text-xs"
                                />
                            </div>
                            <div className="flex flex-wrap gap-2">
                                <Button type="button" variant="outline" onClick={copyExportedData}>
                                    <Copy className="w-4 h-4 mr-2" />
                                    {t('common.copy', 'Copy')}
                                </Button>
                                <Button type="button" variant="outline" onClick={downloadTransferFile}>
                                    <Download className="w-4 h-4 mr-2" />
                                    {t('deviceKey.downloadExport', 'Download export')}
                                </Button>
                            </div>
                            <p className="text-sm text-muted-foreground">
                                {t('deviceKey.exportInstructions')}
                            </p>
                            <DialogFooter>
                                <Button onClick={() => { setShowExportDialog(false); setExportedData(''); setPin(''); }}>
                                    {t('common.close')}
                                </Button>
                            </DialogFooter>
                        </div>
                    )}
                </DialogContent>
            </Dialog>

            {/* Import Dialog */}
            <Dialog open={showImportDialog} onOpenChange={(open) => {
                setShowImportDialog(open);
                if (!open) { setImportData(''); setPin(''); setShowTransferSecret(false); }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.importTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.importDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    <Alert>
                        <AlertTriangle className="w-4 h-4" />
                        <AlertDescription>
                            {t('deviceKey.importWarning')}
                        </AlertDescription>
                    </Alert>
                    <div className="space-y-4">
                        <div className="space-y-2">
                            <Label>{t('deviceKey.transferCode')}</Label>
                            <Textarea
                                value={importData}
                                onChange={(e) => setImportData(e.target.value)}
                                placeholder={t('deviceKey.codePlaceholder')}
                                className="min-h-28 font-mono text-xs"
                            />
                            <Input
                                type="file"
                                accept=".singra-device-key,application/json,text/plain"
                                onChange={(event) => void handleImportFile(event.target.files?.[0])}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>{t('deviceKey.transferPin')}</Label>
                            <div className="flex gap-2">
                                <Input
                                    type={showTransferSecret ? 'text' : 'password'}
                                    value={pin}
                                    onChange={(e) => setPin(e.target.value)}
                                    placeholder={t('deviceKey.pinPlaceholder')}
                                    minLength={DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH}
                                />
                                <Button
                                    type="button"
                                    variant="outline"
                                    size="icon"
                                    onClick={() => setShowTransferSecret((value) => !value)}
                                    aria-label={showTransferSecret ? t('common.hide', 'Hide') : t('common.show', 'Show')}
                                >
                                    {showTransferSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </Button>
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => setPin(generateDeviceKeyTransferSecret())}
                                >
                                    {t('deviceKey.generateSecret')}
                                </Button>
                            </div>
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setShowImportDialog(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleImport} disabled={!importData || pin.length < DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH || loading}>
                            {t('deviceKey.import')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </Card>
    );
}
