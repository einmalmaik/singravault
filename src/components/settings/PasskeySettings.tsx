// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Passkey Settings Component
 *
 * Allows users to register, view, and delete passkeys for vault unlock.
 * Shows PRF support status and provides warnings about passkey limitations.
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Fingerprint, Plus, Trash2, Loader2, ShieldCheck, ShieldAlert, Info, Lock } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import {
    registerPasskey,
    activatePasskeyPrf,
    listPasskeys,
    deletePasskey,
    getPasskeyClientSupport,
    mapRpIdToFriendlyLabel,
    PasskeyCredential,
} from '@/services/passkeyService';
import { isEdgeFunctionServiceError } from '@/services/edgeFunctionService';

export function PasskeySettings() {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user, authReady } = useAuth();
    const { webAuthnAvailable, getPasskeyWrappingMaterial, refreshPasskeyUnlockStatus, isLocked } = useVault();

    const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
    const [loading, setLoading] = useState(false);
    const [registering, setRegistering] = useState(false);
    const [hasPlatformAuth, setHasPlatformAuth] = useState(false);
    const [clientCapabilitiesKnown, setClientCapabilitiesKnown] = useState(false);
    const [prfExtensionSupported, setPrfExtensionSupported] = useState<boolean | null>(null);

    // Registration form
    const [showRegisterForm, setShowRegisterForm] = useState(false);
    const [deviceName, setDeviceName] = useState('');
    const [masterPassword, setMasterPassword] = useState('');

    // Delete confirmation
    const [deleteTarget, setDeleteTarget] = useState<PasskeyCredential | null>(null);
    const [deleting, setDeleting] = useState(false);

    const resolveErrorMessage = useCallback((error: unknown, fallbackMessage: string) => {
        if (isEdgeFunctionServiceError(error)) {
            if (error.status === 401) {
                return t('common.authRequired', 'Your session has expired. Please sign in again.');
            }

            if (error.status === 403) {
                return t('common.forbidden', 'You do not have permission to perform this action.');
            }

            if (error.status && error.status >= 500) {
                return t('common.serviceUnavailable', 'Service temporarily unavailable. Please try again.');
            }
        }

        return error instanceof Error ? error.message : fallbackMessage;
    }, [t]);

    const loadPasskeys = useCallback(async () => {
        if (!authReady || !user) {
            setPasskeys([]);
            return;
        }

        setLoading(true);
        try {
            const creds = await listPasskeys();
            setPasskeys(creds);
            await refreshPasskeyUnlockStatus();
        } catch (error) {
            if (isEdgeFunctionServiceError(error) && error.status === 401) {
                setPasskeys([]);
                return;
            }
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: resolveErrorMessage(error, t('passkey.loadFailed', 'Failed to load passkeys.')),
            });
            setPasskeys([]);
        } finally {
            setLoading(false);
        }
    }, [authReady, refreshPasskeyUnlockStatus, resolveErrorMessage, t, toast, user]); // authReady required — stale closure fix

    useEffect(() => {
        if (authReady && webAuthnAvailable && user) {
            void loadPasskeys();
            void getPasskeyClientSupport().then((support) => {
                setHasPlatformAuth(support.platformAuthenticatorAvailable);
                setClientCapabilitiesKnown(support.clientCapabilitiesAvailable);
                setPrfExtensionSupported(support.prfExtensionSupported);
            });
        }
    }, [authReady, webAuthnAvailable, loadPasskeys, user]);

    const handleRegister = async (e: React.FormEvent) => {
        e.preventDefault();

        if (isLocked) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('passkey.unlockRequired'),
            });
            return;
        }

        if (!masterPassword) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('passkey.passwordRequired', 'Master password is required to register a passkey.'),
            });
            return;
        }

        setRegistering(true);

        // 1. Derive raw key bytes from master password
        const rawKeyBytes = await getPasskeyWrappingMaterial(masterPassword);
        if (!rawKeyBytes) {
            setRegistering(false);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('auth.errors.invalidCredentials'),
            });
            setMasterPassword('');
            return;
        }

        try {
            // 2. Register the passkey
            const result = await registerPasskey(
                rawKeyBytes,
                deviceName || t('passkey.defaultName', 'My Passkey'),
            );

            if (!result.success) {
                if (result.error === 'CANCELLED') {
                    return;
                }

                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: result.error || t('passkey.registerFailed', 'Passkey registration failed.'),
                });
                return;
            }

            // 3. Some authenticators expose PRF only after an additional assertion ceremony.
            let hasVaultUnlock = !!result.prfEnabled && !result.needsPrfActivation;
            if (result.needsPrfActivation) {
                const activationResult = result.credentialId
                    ? await activatePasskeyPrf(rawKeyBytes, result.credentialId)
                    : { success: false, error: 'Missing credential ID for PRF activation' };
                hasVaultUnlock = activationResult.success;

                if (!activationResult.success) {
                    toast({
                        variant: 'destructive',
                        title: t('common.error'),
                        description: activationResult.error || t(
                            'passkey.registeredWithoutPrf',
                            'Passkey registered for authentication, but this device does not support vault unlock (no PRF). You will still need your master password.',
                        ),
                    });
                }
            }

            // 4. Show result
            if (hasVaultUnlock) {
                toast({
                    title: t('common.success'),
                    description: t('passkey.registeredWithPrf', 'Passkey registered! You can now unlock your vault with this passkey.'),
                });
            } else {
                toast({
                    title: t('common.success'),
                    description: t('passkey.registeredWithoutPrf', 'Passkey registered for authentication, but this device does not support vault unlock (no PRF). You will still need your master password.'),
                });
            }

            // 5. Reset form and reload
            setShowRegisterForm(false);
            setDeviceName('');
            setMasterPassword('');
            await loadPasskeys();
        } finally {
            // SECURITY: Wipe raw key bytes
            rawKeyBytes.fill(0);
            setRegistering(false);
        }
    };

    const handleDelete = async () => {
        if (!deleteTarget) return;

        setDeleting(true);
        const result = await deletePasskey(deleteTarget.id);
        setDeleting(false);

        if (result.success) {
            toast({
                title: t('common.success'),
                description: t('passkey.deleted', 'Passkey removed.'),
            });
            setDeleteTarget(null);
            await loadPasskeys();
        } else {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: result.error || t('passkey.deleteFailed', 'Failed to remove passkey.'),
            });
        }
    };

    // Split the unscoped credential list into "usable on this device" and
    // "registered on another device". The server already tags every row
    // with `is_available_on_current_rp` based on `isCredentialAvailableForRp`,
    // so this is a pure presentation split — no security decision lives
    // in the UI. Authentication code paths remain RP-scoped server-side,
    // so a credential listed under "other devices" cannot be used to
    // unlock here even if rendering had a bug.
    const { localPasskeys, remotePasskeys } = useMemo(() => {
        const local: PasskeyCredential[] = [];
        const remote: PasskeyCredential[] = [];
        for (const passkey of passkeys) {
            // `is_available_on_current_rp` is optional on legacy server
            // builds. Treat `undefined` as "available" to preserve the
            // pre-rollout UX: the old endpoint only returned RP-scoped
            // rows, so every entry must be considered local.
            if (passkey.is_available_on_current_rp === false) {
                remote.push(passkey);
            } else {
                local.push(passkey);
            }
        }
        return { localPasskeys: local, remotePasskeys: remote };
    }, [passkeys]);

    const formatDate = (dateStr: string | null) => {
        if (!dateStr) return '—';
        return new Date(dateStr).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    };

    if (!webAuthnAvailable) {
        return null; // Don't render if WebAuthn not supported
    }

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <Fingerprint className="w-5 h-5" />
                    {t('passkey.title', 'Passkeys')}
                </CardTitle>
                <CardDescription>
                    {t('passkey.description', 'Use biometrics or a security key to unlock your vault without typing your master password.')}
                </CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
                {isLocked && (
                    <Alert className="border-amber-500/40 bg-amber-500/10">
                        <Lock className="h-4 w-4 text-amber-600" />
                        <AlertDescription>{t('passkey.unlockRequired')}</AlertDescription>
                    </Alert>
                )}

                {/* Info banner */}
                <div className="flex gap-3 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-sm">
                    <Info className="w-4 h-4 mt-0.5 flex-shrink-0 text-blue-500" />
                    <p className="text-muted-foreground">
                        {t('passkey.infoText', 'Passkeys use the PRF extension to derive an encryption key from your authenticator. Your master password remains as a fallback and can always unlock the vault.')}
                    </p>
                </div>

                {/* Platform authenticator status */}
                {!hasPlatformAuth && (
                    <div className="flex gap-3 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-sm">
                        <ShieldAlert className="w-4 h-4 mt-0.5 flex-shrink-0 text-yellow-500" />
                        <p className="text-muted-foreground">
                            {t('passkey.noPlatformAuth', 'No platform authenticator detected. You can still use a security key (e.g. YubiKey).')}
                        </p>
                    </div>
                )}

                {prfExtensionSupported === false && (
                    <Alert className="border-amber-500/40 bg-amber-500/10">
                        <ShieldAlert className="h-4 w-4 text-amber-600" />
                        <AlertDescription>
                            {t(
                                'passkey.clientPrfUnavailable',
                                'This client supports passkeys, but it does not expose the PRF extension required for vault unlock. You can keep using your master password, but passkey-based vault unlock will not work on this client.',
                            )}
                        </AlertDescription>
                    </Alert>
                )}

                {clientCapabilitiesKnown && prfExtensionSupported === null && (
                    <Alert className="border-blue-500/30 bg-blue-500/10">
                        <Info className="h-4 w-4 text-blue-500" />
                        <AlertDescription>
                            {t(
                                'passkey.clientPrfUnknown',
                                'This client did not report PRF support one way or the other. Passkey registration will verify vault-unlock capability during setup.',
                            )}
                        </AlertDescription>
                    </Alert>
                )}

                {/* Registered passkeys list, split by current-RP availability */}
                {loading ? (
                    <div className="flex justify-center py-6">
                        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                    </div>
                ) : passkeys.length > 0 ? (
                    <div className="space-y-5">
                        {localPasskeys.length > 0 && (
                            <div className="space-y-3">
                                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                                    {t('passkey.sectionThisDevice', 'Auf diesem Gerät verfügbar')}
                                </p>
                                {localPasskeys.map((pk) => (
                                    <PasskeyRow
                                        key={pk.id}
                                        passkey={pk}
                                        isLocal
                                        formatDate={formatDate}
                                        onDelete={() => setDeleteTarget(pk)}
                                        t={t}
                                    />
                                ))}
                            </div>
                        )}
                        {remotePasskeys.length > 0 && (
                            <div className="space-y-3">
                                <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                                    {t('passkey.sectionOtherDevices', 'Andere Geräte / Plattformen')}
                                </p>
                                <p className="text-xs text-muted-foreground">
                                    {t(
                                        'passkey.otherDevicesHint',
                                        'Diese Passkeys sind auf diesem Gerät nicht nutzbar, lassen sich aber von hier aus entfernen.',
                                    )}
                                </p>
                                {remotePasskeys.map((pk) => (
                                    <PasskeyRow
                                        key={pk.id}
                                        passkey={pk}
                                        isLocal={false}
                                        formatDate={formatDate}
                                        onDelete={() => setDeleteTarget(pk)}
                                        t={t}
                                    />
                                ))}
                            </div>
                        )}
                    </div>
                ) : (
                    <p className="text-sm text-muted-foreground text-center py-4">
                        {t('passkey.noPasskeys', 'No passkeys registered yet.')}
                    </p>
                )}

                {/* Register new passkey */}
                {showRegisterForm ? (
                    <form onSubmit={handleRegister} className="space-y-3 p-4 rounded-lg border bg-muted/30">
                        <div className="space-y-2">
                            <Label htmlFor="passkey-name">
                                {t('passkey.deviceNameLabel', 'Passkey name')}
                            </Label>
                            <Input
                                id="passkey-name"
                                value={deviceName}
                                onChange={(e) => setDeviceName(e.target.value)}
                                placeholder={t('passkey.deviceNamePlaceholder', 'e.g. MacBook Touch ID, YubiKey 5')}
                                disabled={registering || isLocked}
                            />
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="passkey-password">
                                {t('passkey.confirmPassword', 'Confirm master password')}
                            </Label>
                            <Input
                                id="passkey-password"
                                type="password"
                                value={masterPassword}
                                onChange={(e) => setMasterPassword(e.target.value)}
                                placeholder="••••••••••••"
                                required
                                disabled={registering || isLocked}
                            />
                            <p className="text-xs text-muted-foreground">
                                {t('passkey.passwordHint', 'Required to securely link the passkey to your vault encryption key.')}
                            </p>
                        </div>

                        <div className="flex gap-2">
                            <Button
                                type="submit"
                                disabled={registering || !masterPassword || isLocked}
                                className="flex-1"
                            >
                                {registering && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                {t('passkey.register', 'Register Passkey')}
                            </Button>
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => {
                                    setShowRegisterForm(false);
                                    setDeviceName('');
                                    setMasterPassword('');
                                }}
                            >
                                {t('common.cancel')}
                            </Button>
                        </div>
                    </form>
                ) : (
                    <Button
                        variant="outline"
                        className="w-full"
                        onClick={() => setShowRegisterForm(true)}
                        disabled={isLocked}
                    >
                        <Plus className="w-4 h-4 mr-2" />
                        {t('passkey.addPasskey', 'Add Passkey')}
                    </Button>
                )}
            </CardContent>

            {/* Delete confirmation dialog */}
            <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>
                            {t('passkey.deleteTitle', 'Remove Passkey?')}
                        </AlertDialogTitle>
                        <AlertDialogDescription>
                            {t(
                                'passkey.deleteDescription',
                                'This will permanently remove "{{name}}". You will no longer be able to unlock your vault with this passkey. Your master password will still work.',
                                { name: deleteTarget?.device_name },
                            )}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel disabled={deleting}>
                            {t('common.cancel')}
                        </AlertDialogCancel>
                        <AlertDialogAction
                            onClick={handleDelete}
                            disabled={deleting}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        >
                            {deleting && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                            {t('common.delete')}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </Card>
    );
}

interface PasskeyRowProps {
    readonly passkey: PasskeyCredential;
    /**
     * Whether this credential can be used to unlock the vault on the
     * current surface. `false` rows are rendered with muted styling and
     * a "registered on another device" hint, but still expose the same
     * delete action — the server enforces ownership-by-user_id, not
     * RP-scope, on delete.
     */
    readonly isLocal: boolean;
    readonly formatDate: (dateStr: string | null) => string;
    readonly onDelete: () => void;
    readonly t: ReturnType<typeof useTranslation>['t'];
}

function PasskeyRow({ passkey, isLocal, formatDate, onDelete, t }: PasskeyRowProps) {
    const platformLabel = mapRpIdToFriendlyLabel(passkey.rp_id);

    return (
        <div
            className={`flex items-center justify-between p-3 rounded-lg border bg-card ${isLocal ? '' : 'opacity-70'}`}
        >
            <div className="flex items-center gap-3">
                <div className={`p-2 rounded-full ${passkey.prf_enabled ? 'bg-green-500/10' : 'bg-muted'}`}>
                    {passkey.prf_enabled ? (
                        <ShieldCheck className="w-4 h-4 text-green-500" />
                    ) : (
                        <Fingerprint className="w-4 h-4 text-muted-foreground" />
                    )}
                </div>
                <div>
                    <p className="font-medium text-sm">{passkey.device_name}</p>
                    <p className="text-xs text-muted-foreground">
                        {platformLabel}
                        {' · '}
                        {t('passkey.created', 'Created')}: {formatDate(passkey.created_at)}
                        {passkey.last_used_at && (
                            <> · {t('passkey.lastUsed', 'Last used')}: {formatDate(passkey.last_used_at)}</>
                        )}
                    </p>
                    <p className="text-xs mt-0.5">
                        {passkey.prf_enabled ? (
                            <span className={isLocal ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'}>
                                {t('passkey.prfEnabled', 'Vault unlock enabled')}
                            </span>
                        ) : (
                            <span className="text-muted-foreground">
                                {t('passkey.prfDisabled', 'Authentication only (no PRF)')}
                            </span>
                        )}
                    </p>
                </div>
            </div>
            <Button
                variant="ghost"
                size="icon"
                className="text-destructive hover:text-destructive"
                onClick={onDelete}
                aria-label={t('passkey.removePasskey', 'Passkey entfernen')}
            >
                <Trash2 className="w-4 h-4" />
            </Button>
        </div>
    );
}

