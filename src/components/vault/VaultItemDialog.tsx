// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Dialog Component
 * 
 * Modal for creating and editing vault items with
 * integrated password generator and TOTP support.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
    Key,
    FileText,
    Shield,
    Lock,
    Eye,
    EyeOff,
    Wand2,
    Star,
    Loader2,
    Trash2,
    Link,
    Folder,
    Plus,
    QrCode
} from 'lucide-react';
import {
    isValidTOTPSecret,
    normalizeTOTPConfig,
    normalizeTOTPSecretInput,
    parseTOTPUri,
    validateTOTPConfig,
    type TOTPAlgorithm,
    type TOTPDigits,
} from '@/services/totpService';
import type { VaultItemData } from '@/services/cryptoService';

import {
    Dialog,
    DialogContent,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import {
    Form,
    FormControl,
    FormField,
    FormItem,
    FormLabel,
    FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
    Collapsible,
    CollapsibleContent,
    CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { Switch } from '@/components/ui/switch';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { PasswordGenerator } from './PasswordGenerator';
import { CategoryIcon } from './CategoryIcon';
import { CategoryDialog } from './CategoryDialog';
import { QRScanner } from './QRScanner';
import { cn } from '@/lib/utils';
import { getExtension, getServiceHooks, isPremiumActive } from '@/extensions/registry';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import {
    buildVaultItemRowFromInsert,
    enqueueOfflineMutation,
    isAppOnline,
    isLikelyOfflineError,
    loadVaultSnapshot,
    removeOfflineItemRow,
    resolveDefaultVaultId,
    shouldUseLocalOnlyVault,
    upsertOfflineCategoryRow,
    upsertOfflineItemRow,
} from '@/services/offlineVaultService';
import {
    ENCRYPTED_CATEGORY_PREFIX,
    neutralizeVaultItemServerMetadata,
} from '@/services/vaultMetadataPolicy';

interface Category {
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
}

const itemSchema = z.object({
    title: z.string().min(1, 'Title is required'),
    url: z.string().optional(), // URL is optional, no strict validation
    username: z.string().optional(),
    password: z.string().optional(),
    notes: z.string().optional(),
    totpSecret: z.string().optional(),
    totpIssuer: z.string().optional(),
    totpLabel: z.string().optional(),
    totpAlgorithm: z.enum(['SHA1', 'SHA256', 'SHA512']).default('SHA1'),
    totpDigits: z.union([z.literal(6), z.literal(8)]).default(6),
    totpPeriod: z.number().int().min(15).max(120).default(30),
    isFavorite: z.boolean().default(false),
});

// Helper to auto-prefix https:// to URLs
const normalizeUrl = (url: string | undefined): string | null => {
    if (!url || url.trim() === '') return null;
    const trimmed = url.trim();
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
        return trimmed;
    }
    return `https://${trimmed}`;
};

type ItemFormData = z.infer<typeof itemSchema>;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEFAULT_TOTP_ALGORITHM: TOTPAlgorithm = 'SHA1';
const DEFAULT_TOTP_DIGITS: TOTPDigits = 6;
const DEFAULT_TOTP_PERIOD = 30;
const EMPTY_ITEM_FORM_VALUES: ItemFormData = {
    title: '',
    url: '',
    username: '',
    password: '',
    notes: '',
    totpSecret: '',
    totpIssuer: '',
    totpLabel: '',
    totpAlgorithm: DEFAULT_TOTP_ALGORITHM,
    totpDigits: DEFAULT_TOTP_DIGITS,
    totpPeriod: DEFAULT_TOTP_PERIOD,
    isFavorite: false,
};

interface VaultItemDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    itemId: string | null;
    onSave?: () => void;
    initialType?: 'password' | 'note' | 'totp';
}

interface PendingAttachmentUploadResult {
    successCount: number;
    failureCount: number;
}

interface VaultFileAttachmentsProps {
    vaultItemId: string | null;
    pendingMode?: boolean;
    onPendingFilesChange?: (count: number) => void;
    onPendingUploadReady?: (uploadPending: ((vaultItemId: string) => Promise<PendingAttachmentUploadResult>) | null) => void;
}

function sanitizeOptionalUuid(value: string | null | undefined): string | null {
    if (!value) return null;
    const trimmed = value.trim();
    if (trimmed === '') return null;
    return UUID_PATTERN.test(trimmed) ? trimmed : null;
}

function clearTotpFormFields(form: ReturnType<typeof useForm<ItemFormData>>): void {
    form.setValue('totpSecret', '');
    form.setValue('totpIssuer', '');
    form.setValue('totpLabel', '');
    form.setValue('totpAlgorithm', DEFAULT_TOTP_ALGORITHM);
    form.setValue('totpDigits', DEFAULT_TOTP_DIGITS);
    form.setValue('totpPeriod', DEFAULT_TOTP_PERIOD);
    form.clearErrors('totpSecret');
}

function resolveInitialItemType(
    initialType: 'password' | 'note' | 'totp',
    hasPremiumAuthenticator: boolean,
    canUseTotp: boolean,
): 'password' | 'note' | 'totp' {
    return initialType === 'totp' && (!hasPremiumAuthenticator || !canUseTotp) ? 'password' : initialType;
}

function clearVaultItemDialogDraftStorage(): void {
    if (typeof window === 'undefined') return;

    [
        'singra:vault-item-dialog:draft',
        'singra-vault-item-dialog-draft',
        'singra-vault-item-draft',
    ].forEach((key) => {
        window.localStorage.removeItem(key);
        window.sessionStorage.removeItem(key);
    });
}

export function buildVaultItemPayloadForEncryption(
    data: ItemFormData,
    itemType: 'password' | 'note' | 'totp',
    selectedCategoryId: string | null,
): VaultItemData {
    const itemData: VaultItemData = {
        title: data.title,
        websiteUrl: itemType === 'note' ? undefined : normalizeUrl(data.url) || undefined,
        itemType,
        isFavorite: data.isFavorite,
        categoryId: sanitizeOptionalUuid(selectedCategoryId),
        username: itemType === 'password' ? data.username : undefined,
        password: itemType === 'password' ? data.password : undefined,
        notes: data.notes,
    };

    if (itemType === 'totp') {
        const config = normalizeTOTPConfig({
            algorithm: data.totpAlgorithm,
            digits: data.totpDigits,
            period: data.totpPeriod,
        }) ?? {
            algorithm: DEFAULT_TOTP_ALGORITHM,
            digits: DEFAULT_TOTP_DIGITS,
            period: DEFAULT_TOTP_PERIOD,
        };

        itemData.totpSecret = normalizeTOTPSecretInput(data.totpSecret || '');
        itemData.totpIssuer = data.totpIssuer?.trim() || undefined;
        itemData.totpLabel = data.totpLabel?.trim() || undefined;
        itemData.totpAlgorithm = config.algorithm;
        itemData.totpDigits = config.digits;
        itemData.totpPeriod = config.period;
    }

    return itemData;
}

export function VaultItemDialog({ open, onOpenChange, itemId, onSave, initialType = 'password' }: VaultItemDialogProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const {
        encryptItem,
        decryptItem,
        encryptData,
        decryptData,
        isDuressMode,
        refreshIntegrityBaseline,
        verifyIntegrity,
    } = useVault();
    const { allowed: canUseTotp, requiredTier } = useFeatureGate('builtin_authenticator');
    const hasPremiumAuthenticator = isPremiumActive();

    const [itemType, setItemType] = useState<'password' | 'note' | 'totp'>(
        resolveInitialItemType(initialType, hasPremiumAuthenticator, canUseTotp)
    );
    const [showPassword, setShowPassword] = useState(false);
    const [showGenerator, setShowGenerator] = useState(false);
    const [showScanner, setShowScanner] = useState(false);
    const [loading, setLoading] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [categories, setCategories] = useState<Category[]>([]);
    const [selectedCategoryId, setSelectedCategoryId] = useState<string | null>(null);
    const [categoryDialogOpen, setCategoryDialogOpen] = useState(false);
    const [pendingAttachmentCount, setPendingAttachmentCount] = useState(0);
    const uploadPendingAttachmentsRef = useRef<((vaultItemId: string) => Promise<PendingAttachmentUploadResult>) | null>(null);

    const vaultPasswordCheck = usePasswordCheck({ enforceStrong: false });

    const normalizedItemId = sanitizeOptionalUuid(itemId);
    const isEditing = !!normalizedItemId;

    const form = useForm<ItemFormData>({
        resolver: zodResolver(itemSchema),
        defaultValues: EMPTY_ITEM_FORM_VALUES,
    });

    const clearSensitiveDialogState = useCallback(() => {
        form.reset(EMPTY_ITEM_FORM_VALUES);
        setItemType(resolveInitialItemType(initialType, hasPremiumAuthenticator, canUseTotp));
        setShowPassword(false);
        setShowGenerator(false);
        setShowScanner(false);
        setSelectedCategoryId(null);
        setCategoryDialogOpen(false);
        setPendingAttachmentCount(0);
        uploadPendingAttachmentsRef.current = null;
        clearVaultItemDialogDraftStorage();
    }, [canUseTotp, form, hasPremiumAuthenticator, initialType]);

    const fetchCategories = useCallback(async () => {
        if (!user || !open) return;
        try {
            const { snapshot, source } = await loadVaultSnapshot(user.id);
            const integrityResult = await verifyIntegrity(snapshot, { source });
            if (integrityResult?.mode === 'blocked') {
                setCategories([]);
                return;
            }

            const canPersistMigrations = integrityResult?.mode === 'healthy'
                && integrityResult.isFirstCheck
                && source === 'remote'
                && !shouldUseLocalOnlyVault(user.id)
                && isAppOnline();
            let integrityBaselineDirty = false;
            const trustedCategoryIds = new Set<string>();
            const resolvedCategories = await Promise.all(
                snapshot.categories.map(async (cat) => {
                    let resolvedName = cat.name;
                    let resolvedIcon = cat.icon;
                    let resolvedColor = cat.color;
                    let migratedName = cat.name;
                    let migratedIcon = cat.icon;
                    let migratedColor = cat.color;

                    if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedName = await decryptData(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category name:', cat.id, err);
                            resolvedName = 'Beschädigte Kategorie';
                        }
                    } else if (canPersistMigrations) {
                        try {
                            const encryptedName = await encryptData(cat.name);
                            migratedName = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedName}`;
                            await supabase
                                .from('categories')
                                .update({ name: migratedName })
                                .eq('id', cat.id);
                            integrityBaselineDirty = true;
                        } catch (err) {
                            console.error('Failed to migrate category name:', cat.id, err);
                        }
                    }

                    if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedIcon = await decryptData(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category icon:', cat.id, err);
                            resolvedIcon = null;
                        }
                    } else if (cat.icon && canPersistMigrations) {
                        try {
                            const encryptedIcon = await encryptData(cat.icon);
                            migratedIcon = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedIcon}`;
                            await supabase
                                .from('categories')
                                .update({ icon: migratedIcon })
                                .eq('id', cat.id);
                            integrityBaselineDirty = true;
                        } catch (err) {
                            console.error('Failed to migrate category icon:', cat.id, err);
                        }
                    }

                    if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedColor = await decryptData(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category color:', cat.id, err);
                            resolvedColor = '#3b82f6';
                        }
                    } else if (cat.color && canPersistMigrations) {
                        try {
                            const encryptedColor = await encryptData(cat.color);
                            migratedColor = `${ENCRYPTED_CATEGORY_PREFIX}${encryptedColor}`;
                            await supabase
                                .from('categories')
                                .update({ color: migratedColor })
                                .eq('id', cat.id);
                            integrityBaselineDirty = true;
                        } catch (err) {
                            console.error('Failed to migrate category color:', cat.id, err);
                        }
                    }

                    if (canPersistMigrations && (migratedName !== cat.name || migratedIcon !== cat.icon || migratedColor !== cat.color)) {
                        await upsertOfflineCategoryRow(user.id, {
                            ...cat,
                            name: migratedName,
                            icon: migratedIcon,
                            color: migratedColor,
                            updated_at: new Date().toISOString(),
                        });
                        trustedCategoryIds.add(cat.id);
                    }

                    return {
                        ...cat,
                        name: resolvedName,
                        icon: resolvedIcon,
                        color: resolvedColor,
                    };
                }),
            );

            if (integrityBaselineDirty && canPersistMigrations) {
                await refreshIntegrityBaseline({
                    categoryIds: trustedCategoryIds,
                });
            }

            setCategories(resolvedCategories);
        } catch (err) {
            console.error('Failed to load categories:', err);
            setCategories([]);
        }
    }, [user, open, decryptData, encryptData, refreshIntegrityBaseline, verifyIntegrity]);

    // Fetch categories
    useEffect(() => {
        fetchCategories();
    }, [fetchCategories]);

    // Load existing item data
    useEffect(() => {
        async function loadItem() {
            if (!normalizedItemId || !open || !user) return;

            setLoading(true);
            try {
                const { snapshot } = await loadVaultSnapshot(user.id);
                const item = snapshot.items.find((entry) => entry.id === normalizedItemId);
                if (!item) {
                    throw new Error('Item not found');
                }

                // Decrypt data
                const decrypted = await decryptItem(item.encrypted_data, normalizedItemId);
                const resolvedTitle = decrypted.title || item.title || '';
                const resolvedUrl = decrypted.websiteUrl || item.website_url || '';
                const resolvedFavorite = typeof decrypted.isFavorite === 'boolean'
                    ? decrypted.isFavorite
                    : !!item.is_favorite;
                const candidateType = decrypted.itemType || item.item_type || 'password';
                const resolvedType: 'password' | 'note' | 'totp' =
                    candidateType === 'note'
                        ? 'note'
                        : candidateType === 'totp' && hasPremiumAuthenticator
                            ? 'totp'
                            : 'password';
                const resolvedCategoryId = decrypted.categoryId ?? item.category_id ?? null;

                form.reset({
                    title: resolvedTitle,
                    url: resolvedUrl,
                    username: decrypted.username || '',
                    password: decrypted.password || '',
                    notes: decrypted.notes || '',
                    totpSecret: normalizeTOTPSecretInput(decrypted.totpSecret || ''),
                    totpIssuer: decrypted.totpIssuer || '',
                    totpLabel: decrypted.totpLabel || '',
                    totpAlgorithm: decrypted.totpAlgorithm || DEFAULT_TOTP_ALGORITHM,
                    totpDigits: decrypted.totpDigits || DEFAULT_TOTP_DIGITS,
                    totpPeriod: decrypted.totpPeriod || DEFAULT_TOTP_PERIOD,
                    isFavorite: resolvedFavorite,
                });

                setItemType(resolvedType);
                setSelectedCategoryId(resolvedCategoryId);
            } catch (err) {
                console.error('Error loading item:', err);
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: 'Failed to load item',
                });
            } finally {
                setLoading(false);
            }
        }

        loadItem();
    }, [normalizedItemId, open, user, decryptItem, form, hasPremiumAuthenticator, toast, t]);

    // Reset create forms every time the dialog opens so sensitive stale values
    // from the previous entry cannot be reused by React state or browser autofill.
    useEffect(() => {
        if (open && !isEditing) {
            clearSensitiveDialogState();
        }
    }, [clearSensitiveDialogState, isEditing, open]);

    // Reset form when dialog closes
    useEffect(() => {
        if (!open) {
            clearSensitiveDialogState();
        }
    }, [clearSensitiveDialogState, open]);

    const onSubmit = async (data: ItemFormData) => {
        if (!user) return;
        if (itemType === 'totp' && (!hasPremiumAuthenticator || !canUseTotp)) {
            toast({
                title: t('subscription.feature_locked_title'),
                description: t('subscription.feature_locked_description', {
                    feature: t('subscription.features.builtin_authenticator'),
                    tier: requiredTier.charAt(0).toUpperCase() + requiredTier.slice(1),
                }),
            });
            return;
        }

        setLoading(true);
        try {
            if (itemType === 'totp' && !isValidTOTPSecret(data.totpSecret || '')) {
                form.setError('totpSecret', {
                    type: 'validate',
                    message: t('authenticator.invalidSecret'),
                });
                return;
            }

            if (itemType === 'totp') {
                const configValidation = validateTOTPConfig({
                    algorithm: data.totpAlgorithm,
                    digits: data.totpDigits,
                    period: data.totpPeriod,
                });
                if (!configValidation.valid) {
                    form.setError('totpSecret', {
                        type: 'validate',
                        message: t('authenticator.unsupportedParameters', {
                            defaultValue: 'Nicht unterstützte TOTP-Parameter.',
                        }),
                    });
                    return;
                }
            }

            let vaultId = sanitizeOptionalUuid(await resolveDefaultVaultId(user.id));
            if (!vaultId) {
                // Create default vault if it doesn't exist
                const { data: newVault, error: vaultError } = await supabase
                    .from('vaults')
                    .insert({
                        user_id: user.id,
                        name: 'Encrypted Vault',
                        is_default: true,
                    })
                    .select('id')
                    .single();

                if (vaultError || !newVault) {
                    throw new Error('Failed to create vault');
                }
                vaultId = newVault.id;
            }
            const canSyncOnline = !shouldUseLocalOnlyVault(user.id) && isAppOnline();

            const itemDataToEncrypt = buildVaultItemPayloadForEncryption(data, itemType, selectedCategoryId);

            // If in duress mode, mark as decoy item (internal marker inside encrypted data)
            const hooks = getServiceHooks();
            const finalItemData = (isDuressMode && hooks.markAsDecoyItem)
                ? hooks.markAsDecoyItem(itemDataToEncrypt)
                : itemDataToEncrypt;

            // SECURITY: Generate or reuse item ID BEFORE encryption so it can
            // be bound as AES-GCM AAD to prevent ciphertext-swap attacks.
            const targetItemId = normalizedItemId ?? crypto.randomUUID();

            // Encrypt sensitive data (with entry ID as AAD)
            const encryptedData = await encryptItem(finalItemData, targetItemId);

            const itemData = neutralizeVaultItemServerMetadata({
                id: targetItemId,
                user_id: user.id,
                vault_id: vaultId,
                encrypted_data: encryptedData,
            });

            let syncedOnline = false;
            let itemRowForCache = buildVaultItemRowFromInsert(itemData);

            if (canSyncOnline) {
                try {
                    const { data: savedItem, error } = await supabase
                        .from('vault_items')
                        .upsert(itemData, { onConflict: 'id' })
                        .select('*')
                        .single();

                    if (error) throw error;
                    if (savedItem) {
                        itemRowForCache = savedItem;
                    }
                    syncedOnline = true;
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            await upsertOfflineItemRow(user.id, itemRowForCache, vaultId);

            if (!syncedOnline) {
                await enqueueOfflineMutation({
                    userId: user.id,
                    type: 'upsert_item',
                    payload: itemData,
                });
            }

            let pendingAttachmentFailureCount = 0;
            if (pendingAttachmentCount > 0) {
                if (syncedOnline && uploadPendingAttachmentsRef.current) {
                    try {
                        const result = await uploadPendingAttachmentsRef.current(targetItemId);
                        pendingAttachmentFailureCount = result.failureCount;
                    } catch {
                        pendingAttachmentFailureCount = pendingAttachmentCount;
                        setPendingAttachmentCount(0);
                        uploadPendingAttachmentsRef.current = null;
                    }
                } else {
                    pendingAttachmentFailureCount = pendingAttachmentCount;
                    setPendingAttachmentCount(0);
                    uploadPendingAttachmentsRef.current = null;
                }
            }

            toast({
                title: t('common.success'),
                description: syncedOnline
                    ? (isEditing ? t('vault.itemUpdated') : t('vault.itemCreated'))
                    : t('vault.offlineSaved', {
                        defaultValue: 'Offline gespeichert. Wird bei Internet automatisch synchronisiert.',
                    }),
            });

            if (pendingAttachmentFailureCount > 0) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: syncedOnline
                        ? t('fileAttachments.pendingUploadFailed', {
                            count: pendingAttachmentFailureCount,
                            defaultValue: '{{count}} Dateianhang/Dateianhänge konnten nicht hochgeladen werden. Der Eintrag wurde ohne diese Anhänge gespeichert.',
                        })
                        : t('fileAttachments.pendingUploadRequiresOnline', {
                            defaultValue: 'Dateianhänge wurden nicht hochgeladen, weil der Eintrag offline gespeichert wurde. Bitte füge sie nach der Synchronisierung erneut hinzu.',
                        }),
                });
            }

            await refreshIntegrityBaseline({
                itemIds: [targetItemId],
            });

            clearSensitiveDialogState();
            onOpenChange(false);
            // Trigger data refresh without page reload
            onSave?.();
        } catch (err) {
            console.error('Error saving item:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: err instanceof Error ? err.message : 'Failed to save item',
            });
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async () => {
        if (!normalizedItemId || !user) return;

        setDeleting(true);
        try {
            let syncedOnline = false;
            const canSyncOnline = !shouldUseLocalOnlyVault(user.id) && isAppOnline();
            if (canSyncOnline) {
                try {
                    const { error } = await supabase
                        .from('vault_items')
                        .delete()
                        .eq('id', normalizedItemId);

                    if (error) throw error;
                    syncedOnline = true;
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            await removeOfflineItemRow(user.id, normalizedItemId);
            if (!syncedOnline) {
                await enqueueOfflineMutation({
                    userId: user.id,
                    type: 'delete_item',
                    payload: { id: normalizedItemId },
                });
            }

            toast({
                title: t('common.success'),
                description: syncedOnline
                    ? t('vault.itemDeleted')
                    : t('vault.offlineDeleteQueued', {
                        defaultValue: 'Offline gelöscht. Löschung wird bei Internet synchronisiert.',
                    }),
            });
            await refreshIntegrityBaseline({
                itemIds: [normalizedItemId],
            });
            onOpenChange(false);
            onSave?.();
        } catch (err) {
            console.error('Error deleting item:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: 'Failed to delete item',
            });
        } finally {
            setDeleting(false);
        }
    };

    const handleGeneratedPassword = (password: string) => {
        form.setValue('password', password, {
            shouldDirty: true,
            shouldTouch: true,
            shouldValidate: true,
        });
    };

    const handleDialogOpenChange = (nextOpen: boolean) => {
        if (!nextOpen) {
            clearSensitiveDialogState();
        }
        onOpenChange(nextOpen);
    };

    return (
        <>
            <Dialog open={open} onOpenChange={handleDialogOpenChange}>
                <DialogContent
                    className="max-w-lg max-h-[90vh] overflow-y-auto"
                    onOpenAutoFocus={(event) => {
                        // On mobile, Radix focusing the first input opens the keyboard immediately.
                        // Let the user decide whether they want to edit text or only adjust metadata.
                        event.preventDefault();
                    }}
                >
                    <DialogHeader>
                        <DialogTitle>
                            {isEditing ? t('vault.editItem') : t('vault.newItem')}
                        </DialogTitle>
                    </DialogHeader>

                    {/* Item Type Tabs */}
                    {!isEditing && (
                        <Tabs
                            value={itemType}
                            onValueChange={(v) => {
                                if (v === 'totp' && !canUseTotp) {
                                    toast({
                                        title: t('subscription.feature_locked_title'),
                                        description: t('subscription.feature_locked_description', {
                                            feature: t('subscription.features.builtin_authenticator'),
                                            tier: requiredTier.charAt(0).toUpperCase() + requiredTier.slice(1),
                                        }),
                                    });
                                    return;
                                }
                                const nextType = v as typeof itemType;
                                if (nextType !== 'totp') {
                                    clearTotpFormFields(form);
                                    setShowScanner(false);
                                }
                                setItemType(nextType);
                            }}
                        >
                            <TabsList className="w-full">
                                <TabsTrigger value="password" className="flex-1">
                                    <Key className="w-4 h-4 mr-2" />
                                    {t('vault.itemTypes.password')}
                                </TabsTrigger>
                                <TabsTrigger value="note" className="flex-1">
                                    <FileText className="w-4 h-4 mr-2" />
                                    {t('vault.itemTypes.note')}
                                </TabsTrigger>
                                {hasPremiumAuthenticator && (
                                    <TabsTrigger value="totp" className="flex-1" disabled={!canUseTotp}>
                                        {canUseTotp
                                            ? <Shield className="w-4 h-4 mr-2" />
                                            : <Lock className="w-4 h-4 mr-2" />
                                        }
                                        {t('vault.itemTypes.totp')}
                                    </TabsTrigger>
                                )}
                            </TabsList>
                        </Tabs>
                    )}

                    <Form {...form}>
                        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" autoComplete="off">
                            {/* Title */}
                            <FormField
                                control={form.control}
                                name="title"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>{t('vault.fields.title')}</FormLabel>
                                        <FormControl>
                                            <Input
                                                placeholder={t('vault.fields.titlePlaceholder')}
                                                autoComplete="off"
                                                {...field}
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* URL (for password type) */}
                            {(itemType === 'password' || itemType === 'totp') && (
                                <FormField
                                    control={form.control}
                                    name="url"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>{t('vault.fields.url')}</FormLabel>
                                            <FormControl>
                                                <div className="relative">
                                                    <Link className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                                                    <Input
                                                        className="pl-10"
                                                        placeholder="example.com"
                                                        autoComplete="off"
                                                        {...field}
                                                        onBlur={(e) => {
                                                            const val = e.target.value.trim();
                                                            if (val && !val.startsWith('http://') && !val.startsWith('https://')) {
                                                                field.onChange(`https://${val}`);
                                                            }
                                                            field.onBlur();
                                                        }}
                                                    />
                                                </div>
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            )}

                            {/* Username */}
                            {itemType === 'password' && (
                                <FormField
                                    control={form.control}
                                    name="username"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>{t('vault.fields.username')}</FormLabel>
                                            <FormControl>
                                                <Input
                                                    placeholder={t('vault.fields.usernamePlaceholder')}
                                                    autoComplete="new-password"
                                                    {...field}
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            )}

                            {/* Password */}
                            {itemType === 'password' && (
                                <FormField
                                    control={form.control}
                                    name="password"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>{t('vault.fields.password')}</FormLabel>
                                            <FormControl>
                                                <div className="flex gap-2">
                                                    <div className="relative flex-1">
                                                        <Input
                                                            type={showPassword ? 'text' : 'password'}
                                                            className="pr-10 font-mono"
                                                            autoComplete="new-password"
                                                            {...field}
                                                            onFocus={vaultPasswordCheck.onFieldFocus}
                                                            onChange={(e) => {
                                                                field.onChange(e);
                                                                vaultPasswordCheck.onPasswordChange(e.target.value);
                                                            }}
                                                            onBlur={(e) => {
                                                                field.onBlur();
                                                                vaultPasswordCheck.onPasswordBlur(e.target.value);
                                                            }}
                                                        />
                                                        <Button
                                                            type="button"
                                                            variant="ghost"
                                                            size="icon"
                                                            className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7"
                                                            onClick={() => setShowPassword(!showPassword)}
                                                        >
                                                            {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                                        </Button>
                                                    </div>
                                                    <Button
                                                        type="button"
                                                        variant="outline"
                                                        size="icon"
                                                        onClick={() => setShowGenerator(!showGenerator)}
                                                    >
                                                        <Wand2 className="w-4 h-4" />
                                                    </Button>
                                                </div>
                                            </FormControl>
                                            {field.value && vaultPasswordCheck.strengthResult && (
                                                <PasswordStrengthMeter
                                                    score={vaultPasswordCheck.strengthResult.score}
                                                    feedback={vaultPasswordCheck.strengthResult.feedback}
                                                    crackTimeDisplay={vaultPasswordCheck.strengthResult.crackTimeDisplay}
                                                    isPwned={vaultPasswordCheck.pwnedResult?.isPwned ?? false}
                                                    pwnedCount={vaultPasswordCheck.pwnedResult?.pwnedCount ?? 0}
                                                    isChecking={vaultPasswordCheck.isChecking}
                                                    compact
                                                />
                                            )}
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            )}

                            {/* Password Generator */}
                            <Collapsible open={showGenerator} onOpenChange={setShowGenerator}>
                                <CollapsibleContent className="mt-2">
                                    <div className="p-4 border rounded-lg bg-muted/50">
                                        <PasswordGenerator onSelect={handleGeneratedPassword} />
                                    </div>
                                </CollapsibleContent>
                            </Collapsible>

                            {/* TOTP Secret */}
                            {itemType === 'totp' && (
                                <FormField
                                    control={form.control}
                                    name="totpSecret"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>{t('vault.fields.totpSecret')}</FormLabel>
                                            <div className="flex gap-2">
                                                <FormControl>
                                                    <Input
                                                        placeholder="JBSWY3DPEHPK3PXP"
                                                        className="font-mono"
                                                        autoComplete="new-password"
                                                        {...field}
                                                        onChange={(event) => {
                                                            field.onChange(normalizeTOTPSecretInput(event.target.value));
                                                        }}
                                                    />
                                                </FormControl>
                                                <Button
                                                    type="button"
                                                    variant="outline"
                                                    size="icon"
                                                    onClick={() => setShowScanner(true)}
                                                    title={t('authenticator.scanQr')}
                                                >
                                                    <QrCode className="w-4 h-4" />
                                                </Button>
                                            </div>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            )}

                            {/* File Attachments (Premium) */}
                            {(() => {
                                const FileAttachmentsComp = getExtension<VaultFileAttachmentsProps>('vault.file-attachments');
                                return FileAttachmentsComp ? (
                                    <div className="pt-4">
                                        <FileAttachmentsComp
                                            vaultItemId={normalizedItemId}
                                            pendingMode={!normalizedItemId}
                                            onPendingFilesChange={setPendingAttachmentCount}
                                            onPendingUploadReady={(uploadPending) => {
                                                uploadPendingAttachmentsRef.current = uploadPending;
                                            }}
                                        />
                                    </div>
                                ) : null;
                            })()}

                            {/* Notes */}
                            <FormField
                                control={form.control}
                                name="notes"
                                render={({ field }) => (
                                    <FormItem>
                                        <FormLabel>{t('vault.fields.notes')}</FormLabel>
                                        <FormControl>
                                            <Textarea
                                                placeholder={t('vault.fields.notesPlaceholder')}
                                                rows={3}
                                                autoComplete="off"
                                                {...field}
                                            />
                                        </FormControl>
                                        <FormMessage />
                                    </FormItem>
                                )}
                            />

                            {/* Category */}
                            <FormItem>
                                <FormLabel>{t('vault.form.category')}</FormLabel>
                                <div className="flex gap-2">
                                    <Select
                                        value={selectedCategoryId ?? '__none__'}
                                        onValueChange={(value) => {
                                            setSelectedCategoryId(value === '__none__' ? null : value);
                                        }}
                                    >
                                        <SelectTrigger className="flex-1">
                                            <SelectValue placeholder={t('vault.form.selectCategory')} />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="__none__">
                                                <span className="inline-flex items-center gap-2">
                                                    <Folder className="w-4 h-4 text-muted-foreground" />
                                                    {t('vault.categories.uncategorized')}
                                                </span>
                                            </SelectItem>
                                            {categories.map((category) => (
                                                <SelectItem key={category.id} value={category.id}>
                                                    <span className="inline-flex items-center gap-2">
                                                        <span style={category.color ? { color: category.color } : undefined}>
                                                            <CategoryIcon icon={category.icon} className="w-4 h-4" />
                                                        </span>
                                                        {category.name}
                                                    </span>
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="icon"
                                        onClick={() => setCategoryDialogOpen(true)}
                                        title={t('vault.categories.addCategory')}
                                    >
                                        <Plus className="w-4 h-4" />
                                    </Button>
                                </div>
                            </FormItem>

                            {/* Favorite Toggle */}
                            <FormField
                                control={form.control}
                                name="isFavorite"
                                render={({ field }) => (
                                    <FormItem className="flex items-center justify-between">
                                        <FormLabel className="flex items-center gap-2">
                                            <Star className={cn('w-4 h-4', field.value && 'text-amber-500 fill-amber-500')} />
                                            {t('vault.fields.favorite')}
                                        </FormLabel>
                                        <FormControl>
                                            <Switch
                                                checked={field.value}
                                                onCheckedChange={field.onChange}
                                            />
                                        </FormControl>
                                    </FormItem>
                                )}
                            />

                            {/* Actions */}
                            <div className="flex gap-2 pt-4 border-t">
                                {isEditing && (
                                    <Button
                                        type="button"
                                        variant="destructive"
                                        onClick={handleDelete}
                                        disabled={loading || deleting}
                                    >
                                        {deleting ? (
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <Trash2 className="w-4 h-4" />
                                        )}
                                    </Button>
                                )}
                                <div className="flex-1" />
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => onOpenChange(false)}
                                    disabled={loading}
                                >
                                    {t('common.cancel')}
                                </Button>
                                <Button type="submit" disabled={loading}>
                                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    {isEditing ? t('common.save') : t('common.create')}
                                </Button>
                            </div>
                        </form>
                    </Form>
                </DialogContent>
            </Dialog>

            {/* QR Scanner Dialog */}
            <Dialog open={showScanner && itemType === 'totp' && hasPremiumAuthenticator && canUseTotp} onOpenChange={setShowScanner}>
                <DialogContent className="sm:max-w-md">
                    <DialogHeader>
                        <DialogTitle>{t('authenticator.scanQr')}</DialogTitle>
                    </DialogHeader>
                    <div className="aspect-square">
                        <QRScanner
                            onScan={(code) => {
                                const uri = parseTOTPUri(code);
                                if (uri) {
                                    form.setValue('totpSecret', normalizeTOTPSecretInput(uri.secret));
                                    form.setValue('totpIssuer', uri.issuer);
                                    form.setValue('totpLabel', uri.label);
                                    form.setValue('totpAlgorithm', uri.algorithm || DEFAULT_TOTP_ALGORITHM);
                                    form.setValue('totpDigits', uri.digits || DEFAULT_TOTP_DIGITS);
                                    form.setValue('totpPeriod', uri.period || DEFAULT_TOTP_PERIOD);
                                    form.clearErrors('totpSecret');
                                    if (uri.issuer && !form.getValues('title')) {
                                        form.setValue('title', `${uri.issuer} (${uri.label})`);
                                    }
                                } else {
                                    const normalizedCode = normalizeTOTPSecretInput(code);
                                    if (isValidTOTPSecret(normalizedCode)) {
                                        form.setValue('totpSecret', normalizedCode);
                                        form.setValue('totpAlgorithm', DEFAULT_TOTP_ALGORITHM);
                                        form.setValue('totpDigits', DEFAULT_TOTP_DIGITS);
                                        form.setValue('totpPeriod', DEFAULT_TOTP_PERIOD);
                                        form.clearErrors('totpSecret');
                                    } else {
                                        form.setError('totpSecret', {
                                            type: 'validate',
                                            message: t('authenticator.unsupportedQr', {
                                                defaultValue: 'Ungültiger oder nicht unterstützter TOTP-QR-Code.',
                                            }),
                                        });
                                    }
                                }
                                setShowScanner(false);
                            }}
                            onClose={() => setShowScanner(false)}
                        />
                    </div>
                </DialogContent>
            </Dialog>

            <CategoryDialog
                open={categoryDialogOpen}
                onOpenChange={setCategoryDialogOpen}
                category={null}
                onSave={fetchCategories}
            />
        </>
    );
}



