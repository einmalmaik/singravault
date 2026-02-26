// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Device Key Settings Component
 *
 * Allows users to enable Device Key protection, export their
 * device key for transfer to other devices, and import a device
 * key from another device.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, QrCode, Upload, Shield, AlertTriangle } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogFooter,
} from '@/components/ui/dialog';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import {
    exportDeviceKeyForTransfer,
    importDeviceKeyFromTransfer,
} from '@/services/deviceKeyService';

export function DeviceKeySettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { deviceKeyActive, enableDeviceKey, isLocked } = useVault();
    const { user } = useAuth();

    const [showEnableDialog, setShowEnableDialog] = useState(false);
    const [showExportDialog, setShowExportDialog] = useState(false);
    const [showImportDialog, setShowImportDialog] = useState(false);
    const [masterPassword, setMasterPassword] = useState('');
    const [pin, setPin] = useState('');
    const [exportedData, setExportedData] = useState('');
    const [importData, setImportData] = useState('');
    const [loading, setLoading] = useState(false);

    const handleEnable = async () => {
        if (!masterPassword) return;
        setLoading(true);

        const { error } = await enableDeviceKey(masterPassword);

        setLoading(false);
        setShowEnableDialog(false);
        setMasterPassword('');

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.enableFailed'),
            });
        } else {
            toast({
                title: t('common.success'),
                description: t('deviceKey.enableSuccess'),
            });
        }
    };

    const handleExport = async () => {
        if (!user || !pin || pin.length < 4) return;
        setLoading(true);

        const data = await exportDeviceKeyForTransfer(user.id, pin);

        setLoading(false);
        if (data) {
            setExportedData(data);
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.exportFailed'),
            });
        }
    };

    const handleImport = async () => {
        if (!user || !importData || !pin || pin.length < 4) return;
        setLoading(true);

        const success = await importDeviceKeyFromTransfer(user.id, importData, pin);

        setLoading(false);
        setShowImportDialog(false);
        setImportData('');
        setPin('');

        if (success) {
            toast({
                title: t('common.success'),
                description: t('deviceKey.importSuccess'),
            });
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('deviceKey.importFailed'),
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
                    <div className="space-y-2">
                        <Label>{t('auth.unlock.password')}</Label>
                        <Input
                            type="password"
                            value={masterPassword}
                            onChange={(e) => setMasterPassword(e.target.value)}
                            placeholder="••••••••••••"
                        />
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setShowEnableDialog(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleEnable} disabled={!masterPassword || loading}>
                            {t('deviceKey.enable')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Export Dialog */}
            <Dialog open={showExportDialog} onOpenChange={(open) => {
                setShowExportDialog(open);
                if (!open) { setExportedData(''); setPin(''); }
            }}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.exportTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.exportDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    {!exportedData ? (
                        <>
                            <div className="space-y-2">
                                <Label>{t('deviceKey.transferPin')}</Label>
                                <Input
                                    type="password"
                                    value={pin}
                                    onChange={(e) => setPin(e.target.value)}
                                    placeholder={t('deviceKey.pinPlaceholder')}
                                    minLength={4}
                                />
                            </div>
                            <DialogFooter>
                                <Button variant="outline" onClick={() => setShowExportDialog(false)}>
                                    {t('common.cancel')}
                                </Button>
                                <Button onClick={handleExport} disabled={pin.length < 4 || loading}>
                                    {t('deviceKey.generateCode')}
                                </Button>
                            </DialogFooter>
                        </>
                    ) : (
                        <div className="space-y-4">
                            <div className="p-4 rounded-lg bg-muted font-mono text-xs break-all select-all">
                                {exportedData}
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
            <Dialog open={showImportDialog} onOpenChange={setShowImportDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>{t('deviceKey.importTitle')}</DialogTitle>
                        <DialogDescription>
                            {t('deviceKey.importDesc')}
                        </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4">
                        <div className="space-y-2">
                            <Label>{t('deviceKey.transferCode')}</Label>
                            <Input
                                value={importData}
                                onChange={(e) => setImportData(e.target.value)}
                                placeholder={t('deviceKey.codePlaceholder')}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>{t('deviceKey.transferPin')}</Label>
                            <Input
                                type="password"
                                value={pin}
                                onChange={(e) => setPin(e.target.value)}
                                placeholder={t('deviceKey.pinPlaceholder')}
                            />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant="outline" onClick={() => setShowImportDialog(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleImport} disabled={!importData || pin.length < 4 || loading}>
                            {t('deviceKey.import')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </Card>
    );
}
