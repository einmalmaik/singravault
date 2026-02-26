// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Security Settings Component
 * 
 * Security-related settings including auto-lock timer, vault lock, and 2FA
 */

import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Shield, Lock, Timer } from 'lucide-react';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';

import { TwoFactorSettings } from './TwoFactorSettings';
import { PasskeySettings } from './PasskeySettings';
import { DeviceKeySettings } from './DeviceKeySettings';
import { getExtension } from '@/extensions/registry';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';

const AUTO_LOCK_OPTIONS = [
    { value: '60000', label: '1 min' },
    { value: '300000', label: '5 min' },
    { value: '900000', label: '15 min' },
    { value: '1800000', label: '30 min' },
    { value: '3600000', label: '1 h' },
    { value: '0', label: 'settings.security.never' },
];

export function SecuritySettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const navigate = useNavigate();
    const { autoLockTimeout, setAutoLockTimeout, lock, isLocked } = useVault();
    const DuressSettings = getExtension('settings.duress');

    const handleAutoLockChange = (value: string) => {
        const timeout = parseInt(value, 10);
        setAutoLockTimeout(timeout);

        // Persist to localStorage
        localStorage.setItem('singra_autolock', value);

        toast({
            title: t('common.success'),
            description: t('settings.security.autoLockUpdated'),
        });
    };

    const handleLockNow = () => {
        lock();
        toast({
            title: t('settings.security.vaultLocked'),
            description: t('settings.security.vaultLockedDesc'),
        });
        // Navigate to vault with replace to prevent back navigation
        navigate('/vault', { replace: true });
    };

    return (
        <>
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="w-5 h-5" />
                        {t('settings.security.title')}
                    </CardTitle>
                    <CardDescription>
                        {t('settings.security.description')}
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                    {/* Auto-Lock Timer */}
                    <div className="space-y-2">
                        <Label className="flex items-center gap-2">
                            <Timer className="w-4 h-4" />
                            {t('settings.security.autoLock')}
                        </Label>
                        <Select
                            value={autoLockTimeout.toString()}
                            onValueChange={handleAutoLockChange}
                        >
                            <SelectTrigger className="w-full sm:w-[200px]">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                {AUTO_LOCK_OPTIONS.map((option) => (
                                    <SelectItem key={option.value} value={option.value}>
                                        {option.label.startsWith('settings.')
                                            ? t(option.label)
                                            : option.label}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                        <p className="text-sm text-muted-foreground">
                            {t('settings.security.autoLockDesc')}
                        </p>
                    </div>

                    {/* Lock Now Button */}
                    <div className="space-y-2">
                        <Label className="flex items-center gap-2">
                            <Lock className="w-4 h-4" />
                            {t('settings.security.manualLock')}
                        </Label>
                        <Button
                            variant="outline"
                            onClick={handleLockNow}
                            disabled={isLocked}
                            className="flex items-center gap-2"
                        >
                            <Lock className="w-4 h-4" />
                            {t('settings.security.lockNow')}
                        </Button>
                    </div>
                </CardContent>
            </Card>

            {/* Two-Factor Authentication */}
            <Separator className="my-6" />
            <TwoFactorSettings />

            {/* Passkey Authentication */}
            <Separator className="my-6" />
            <PasskeySettings />

            {/* Panic/Duress Password (Premium) */}
            {DuressSettings && (
                <>
                    <Separator className="my-6" />
                    <DuressSettings />
                </>
            )}

            {/* Device Key Protection */}
            <Separator className="my-6" />
            <DeviceKeySettings />
        </>
    );
}
