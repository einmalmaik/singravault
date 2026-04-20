// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Two-Factor Authentication Settings Component
 * 
 * Provides a multi-step setup flow for enabling 2FA:
 * 1. QR code display (or manual secret entry)
 * 2. Code verification
 * 3. Backup codes display and download
 * 
 * Also handles disabling 2FA with security checks.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
    Shield,
    Smartphone,
    QrCode,
    Key,
    Download,
    Check,
    AlertTriangle,
    Loader2,
    Copy,
    Eye,
    EyeOff,
    RefreshCw,
    Lock,
} from 'lucide-react';
import QRCode from 'qrcode';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Separator } from '@/components/ui/separator';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import {
    Alert,
    AlertDescription,
    AlertTitle,
} from '@/components/ui/alert';

import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import {
    generateTOTPSecret,
    generateQRCodeUri,
    formatSecretForDisplay,
    generateBackupCodes,
    get2FAStatus,
    initializeTwoFactorSetup,
    enableTwoFactor,
    disableTwoFactor,
    setVaultTwoFactor,
    regenerateBackupCodes,
    TwoFactorStatus,
} from '@/services/twoFactorService';
import { writeClipboard } from '@/services/clipboardService';
import { saveExportFile } from '@/services/exportFileService';

type SetupStep = 'idle' | 'qrcode' | 'verify' | 'backup' | 'complete';

export function TwoFactorSettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();

    // State
    const [status, setStatus] = useState<TwoFactorStatus | null>(null);
    const [loading, setLoading] = useState(true);
    const [setupStep, setSetupStep] = useState<SetupStep>('idle');
    const [secret, setSecret] = useState('');
    const [qrCodeDataUrl, setQrCodeDataUrl] = useState('');
    const [showSecret, setShowSecret] = useState(false);
    const [verificationCode, setVerificationCode] = useState('');
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [verifying, setVerifying] = useState(false);
    const [error, setError] = useState('');

    // Disable dialog state
    const [showDisableDialog, setShowDisableDialog] = useState(false);
    const [disableCode, setDisableCode] = useState('');
    const [disabling, setDisabling] = useState(false);

    // Load 2FA status
    useEffect(() => {
        if (user?.id) {
            loadStatus();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [user?.id]);

    const loadStatus = async () => {
        if (!user?.id) return;
        setLoading(true);
        const result = await get2FAStatus(user.id);
        setStatus(result);
        setLoading(false);
    };

    // Generate QR code when setup starts
    const startSetup = async () => {
        if (!user?.id || !user?.email) return;

        setError('');
        const newSecret = generateTOTPSecret();
        setSecret(newSecret);

        // Initialize in database
        const result = await initializeTwoFactorSetup(user.id, newSecret);
        if (!result.success) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: result.error,
            });
            return;
        }

        // Generate QR code
        const uri = generateQRCodeUri(newSecret, user.email);
        try {
            const dataUrl = await QRCode.toDataURL(uri, {
                width: 200,
                margin: 2,
                errorCorrectionLevel: 'M',
            });
            setQrCodeDataUrl(dataUrl);
        } catch (err) {
            console.error('QR code generation error:', err);
        }

        // Generate backup codes
        const codes = generateBackupCodes();
        setBackupCodes(codes);

        setSetupStep('qrcode');
    };

    // Handle verification
    const handleVerify = async () => {
        if (!user?.id || verificationCode.length < 6) return;

        setVerifying(true);
        setError('');

        const result = await enableTwoFactor(user.id, verificationCode, backupCodes);

        if (result.success) {
            setSetupStep('backup');
            await loadStatus();
        } else {
            setError(result.error || t('settings.security.twoFactor.verify.invalid'));
        }

        setVerifying(false);
    };

    // Handle code input (auto-submit on 6 digits)
    const handleCodeInput = (value: string) => {
        const cleaned = value.replace(/\D/g, '').slice(0, 6);
        setVerificationCode(cleaned);
    };

    // Download backup codes
    const downloadBackupCodes = async () => {
        const content = [
            'Singra Vault - Backup Codes',
            '========================',
            '',
            'Diese Codes können jeweils einmal verwendet werden, falls du keinen Zugriff auf deine Authenticator-App hast.',
            '',
            ...backupCodes.map((code, i) => `${i + 1}. ${code}`),
            '',
            `Erstellt am: ${new Date().toLocaleDateString('de-DE')}`,
        ].join('\n');

        const saved = await saveExportFile({
            name: 'singra-backup-codes.txt',
            mime: 'text/plain',
            content,
        });

        if (!saved) {
            return;
        }

        toast({
            title: t('common.success'),
            description: t('settings.security.twoFactor.setup.downloadCodes'),
        });
    };

    // Copy secret to clipboard
    const copySecret = async () => {
        try {
            await writeClipboard(secret);
            toast({
                title: t('common.copied'),
                description: `${t('settings.security.twoFactor.setup.manualEntry')} ${t('vault.clipboardAutoClear')}`,
            });
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('vault.copyFailed'),
            });
        }
    };

    // Handle disable 2FA
    const handleDisable = async () => {
        if (!user?.id) return;

        setDisabling(true);
        setError('');

        const result = await disableTwoFactor(user.id, disableCode);

        if (result.success) {
            setShowDisableDialog(false);
            setDisableCode('');
            await loadStatus();
            toast({
                title: t('common.success'),
                description: t('settings.security.twoFactor.disableDialog.success'),
            });
        } else {
            setError(result.error || t('settings.security.twoFactor.verify.invalid'));
        }

        setDisabling(false);
    };

    // Toggle vault 2FA
    const handleVaultToggle = async (enabled: boolean) => {
        if (!user?.id) return;

        const result = await setVaultTwoFactor(user.id, enabled);

        if (result.success) {
            await loadStatus();
            toast({
                title: t('common.success'),
                description: enabled
                    ? t('settings.security.twoFactor.vault.enabled')
                    : t('settings.security.twoFactor.vault.disabled'),
            });
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: result.error,
            });
        }
    };

    // Regenerate backup codes
    const handleRegenerateBackupCodes = async () => {
        if (!user?.id) return;

        const result = await regenerateBackupCodes(user.id);

        if (result.success && result.codes) {
            setBackupCodes(result.codes);
            setSetupStep('backup');
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: result.error,
            });
        }
    };

    // Complete setup
    const completeSetup = () => {
        setSetupStep('idle');
        setSecret('');
        setQrCodeDataUrl('');
        setVerificationCode('');
        setBackupCodes([]);
    };

    if (loading) {
        return (
            <Card>
                <CardContent className="py-8 flex items-center justify-center">
                    <Loader2 className="w-6 h-6 animate-spin" />
                </CardContent>
            </Card>
        );
    }

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Smartphone className="w-5 h-5" />
                        {t('settings.security.twoFactor.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.security.twoFactor.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    {/* Status indicator */}
                    {status?.isEnabled ? (
                        <Alert className="border-green-500/50 bg-green-500/10">
                            <Shield className="h-4 w-4 text-green-500" />
                            <AlertTitle className="text-green-500">
                                {t('settings.security.twoFactor.enabled')}
                            </AlertTitle>
                            <AlertDescription>
                                {t('settings.security.twoFactor.backupCodesRemaining', {
                                    count: status.backupCodesRemaining,
                                })}
                            </AlertDescription>
                        </Alert>
                    ) : setupStep === 'idle' ? (
                        <Alert>
                            <AlertTriangle className="h-4 w-4" />
                            <AlertTitle>{t('settings.security.twoFactor.disabled')}</AlertTitle>
                            <AlertDescription>
                                {t('settings.security.twoFactor.disabledDesc')}
                            </AlertDescription>
                        </Alert>
                    ) : null}

                    {/* Setup Flow */}
                    {setupStep === 'qrcode' && (
                        <div className="space-y-6">
                            <div className="text-center space-y-4">
                                <h3 className="font-semibold">
                                    {t('settings.security.twoFactor.setup.step1Title')}
                                </h3>
                                <p className="text-sm text-muted-foreground">
                                    {t('settings.security.twoFactor.setup.step1Desc')}
                                </p>

                                {/* QR Code */}
                                {qrCodeDataUrl && (
                                    <div className="flex justify-center">
                                        <div className="p-4 bg-white rounded-lg">
                                            <img
                                                src={qrCodeDataUrl}
                                                alt="2FA QR Code"
                                                className="w-[200px] h-[200px]"
                                            />
                                        </div>
                                    </div>
                                )}

                                {/* Manual entry toggle */}
                                <div className="space-y-2">
                                    <Button
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => setShowSecret(!showSecret)}
                                    >
                                        {showSecret ? (
                                            <EyeOff className="w-4 h-4 mr-2" />
                                        ) : (
                                            <Eye className="w-4 h-4 mr-2" />
                                        )}
                                        {t('settings.security.twoFactor.setup.cantScan')}
                                    </Button>

                                    {showSecret && (
                                        <div className="p-4 bg-muted rounded-lg space-y-2">
                                            <p className="text-xs text-muted-foreground">
                                                {t('settings.security.twoFactor.setup.manualEntry')}
                                            </p>
                                            <div className="flex items-center gap-2 justify-center">
                                                <code className="px-3 py-2 bg-background rounded font-mono text-sm">
                                                    {formatSecretForDisplay(secret)}
                                                </code>
                                                <Button
                                                    variant="ghost"
                                                    size="icon"
                                                    onClick={copySecret}
                                                >
                                                    <Copy className="w-4 h-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>

                            <div className="flex justify-end gap-2">
                                <Button variant="outline" onClick={() => setSetupStep('idle')}>
                                    {t('common.cancel')}
                                </Button>
                                <Button onClick={() => setSetupStep('verify')}>
                                    {t('common.next')}
                                </Button>
                            </div>
                        </div>
                    )}

                    {setupStep === 'verify' && (
                        <div className="space-y-6">
                            <div className="text-center space-y-4">
                                <h3 className="font-semibold">
                                    {t('settings.security.twoFactor.setup.step2Title')}
                                </h3>
                                <p className="text-sm text-muted-foreground">
                                    {t('settings.security.twoFactor.setup.step2Desc')}
                                </p>

                                {/* Code input */}
                                <div className="flex justify-center">
                                    <Input
                                        type="text"
                                        inputMode="numeric"
                                        value={verificationCode}
                                        onChange={(e) => handleCodeInput(e.target.value)}
                                        placeholder="000000"
                                        className="w-40 text-center text-2xl font-mono tracking-widest"
                                        maxLength={6}
                                    />
                                </div>

                                {error && (
                                    <p className="text-sm text-destructive">{error}</p>
                                )}
                            </div>

                            <div className="flex justify-end gap-2">
                                <Button
                                    variant="outline"
                                    onClick={() => setSetupStep('qrcode')}
                                >
                                    {t('common.back')}
                                </Button>
                                <Button
                                    onClick={handleVerify}
                                    disabled={verificationCode.length < 6 || verifying}
                                >
                                    {verifying && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    {t('common.next')}
                                </Button>
                            </div>
                        </div>
                    )}

                    {setupStep === 'backup' && (
                        <div className="space-y-6">
                            <div className="text-center space-y-4">
                                <div className="flex justify-center">
                                    <div className="w-12 h-12 rounded-full bg-green-500/20 flex items-center justify-center">
                                        <Check className="w-6 h-6 text-green-500" />
                                    </div>
                                </div>
                                <h3 className="font-semibold">
                                    {t('settings.security.twoFactor.setup.step3Title')}
                                </h3>
                                <p className="text-sm text-muted-foreground">
                                    {t('settings.security.twoFactor.setup.step3Desc')}
                                </p>

                                {/* Backup codes */}
                                <div className="p-4 bg-muted rounded-lg space-y-3">
                                    <div className="grid grid-cols-2 gap-2">
                                        {backupCodes.map((code, i) => (
                                            <code
                                                key={i}
                                                className="px-3 py-2 bg-background rounded font-mono text-sm"
                                            >
                                                {code}
                                            </code>
                                        ))}
                                    </div>
                                    <Button
                                        variant="outline"
                                        className="w-full"
                                        onClick={downloadBackupCodes}
                                    >
                                        <Download className="w-4 h-4 mr-2" />
                                        {t('settings.security.twoFactor.setup.downloadCodes')}
                                    </Button>
                                </div>

                                <Alert variant="destructive">
                                    <AlertTriangle className="h-4 w-4" />
                                    <AlertDescription>
                                        {t('settings.security.twoFactor.setup.codesWarning')}
                                    </AlertDescription>
                                </Alert>
                            </div>

                            <div className="flex justify-end">
                                <Button onClick={completeSetup}>
                                    {t('common.close')}
                                </Button>
                            </div>
                        </div>
                    )}

                    {/* Idle state actions */}
                    {setupStep === 'idle' && !status?.isEnabled && (
                        <Button onClick={startSetup} className="w-full">
                            <QrCode className="w-4 h-4 mr-2" />
                            {t('settings.security.twoFactor.enable')}
                        </Button>
                    )}

                    {/* Enabled state actions */}
                    {setupStep === 'idle' && status?.isEnabled && (
                        <>
                            <Separator />

                            {/* Vault 2FA toggle */}
                            <div className="flex items-center justify-between">
                                <div className="space-y-0.5">
                                    <Label className="flex items-center gap-2">
                                        <Lock className="w-4 h-4" />
                                        {t('settings.security.twoFactor.vault.title')}
                                    </Label>
                                    <p className="text-sm text-muted-foreground">
                                        {t('settings.security.twoFactor.vault.description')}
                                    </p>
                                </div>
                                <Switch
                                    checked={status.vaultTwoFactorEnabled}
                                    onCheckedChange={handleVaultToggle}
                                />
                            </div>

                            <Separator />

                            {/* Actions */}
                            <div className="flex flex-col gap-2">
                                <Button
                                    variant="outline"
                                    onClick={handleRegenerateBackupCodes}
                                >
                                    <RefreshCw className="w-4 h-4 mr-2" />
                                    {t('settings.security.twoFactor.regenerateCodes')}
                                </Button>
                                <Button
                                    variant="destructive"
                                    onClick={() => setShowDisableDialog(true)}
                                >
                                    {t('settings.security.twoFactor.disable')}
                                </Button>
                            </div>
                        </>
                    )}
                </CardContent>
            </Card>

            {/* Disable 2FA Dialog */}
            <Dialog open={showDisableDialog} onOpenChange={setShowDisableDialog}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>
                            {t('settings.security.twoFactor.disableDialog.title')}
                        </DialogTitle>
                        <DialogDescription>
                            {t('settings.security.twoFactor.disableDialog.description')}
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4">
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                                {t('settings.security.twoFactor.disableDialog.backupCodeNotAllowed')}
                            </AlertDescription>
                        </Alert>

                        <div className="space-y-2">
                            <Label>{t('settings.security.twoFactor.verify.title')}</Label>
                            <Input
                                type="text"
                                inputMode="numeric"
                                value={disableCode}
                                onChange={(e) =>
                                    setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                                }
                                placeholder="000000"
                                className="text-center text-xl font-mono tracking-widest"
                                maxLength={6}
                            />
                        </div>

                        {error && <p className="text-sm text-destructive">{error}</p>}
                    </div>

                    <DialogFooter>
                        <Button
                            variant="outline"
                            onClick={() => {
                                setShowDisableDialog(false);
                                setDisableCode('');
                                setError('');
                            }}
                        >
                            {t('common.cancel')}
                        </Button>
                        <Button
                            variant="destructive"
                            onClick={handleDisable}
                            disabled={disableCode.length < 6 || disabling}
                        >
                            {disabling && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('settings.security.twoFactor.disable')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </>
    );
}
