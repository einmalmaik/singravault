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
import { PasswordGenerator } from './PasswordGenerator';
import { CategoryIcon } from './CategoryIcon';
import { CategoryDialog } from './CategoryDialog';
import { QRScanner } from './QRScanner';
import { cn } from '@/lib/utils';
import { getExtension, isPremiumActive } from '@/extensions/registry';
import { usePasswordCheck } from '@/hooks/usePasswordCheck';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import { PasswordStrengthMeter } from '@/components/ui/PasswordStrengthMeter';
import {
    loadVaultSnapshot,
} from '@/services/offlineVaultService';
import {
    ENCRYPTED_CATEGORY_PREFIX,
} from '@/services/vaultMetadataPolicy';
import type { ItemPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';

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
const OPLOG_TEXT_DECODER = new TextDecoder();

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

function shouldVerifyLegacyDialogCategorySnapshot(
    vaultMigrationStatus: VaultMigrationRolloutStatus | null,
): boolean {
    return vaultMigrationStatus !== 'verified';
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

function buildOpLogItemPlaintext(itemData: VaultItemData): ItemPlaintext {
    return {
        title: itemData.title ?? '',
        websiteUrl: itemData.websiteUrl ?? null,
        username: itemData.username ?? null,
        password: itemData.password ?? null,
        notes: itemData.notes ?? null,
        itemType: itemData.itemType === 'note'
            ? 'note'
            : itemData.itemType === 'totp'
                ? 'totp'
                : itemData.itemType === 'card'
                    ? 'card'
                    : 'password',
        categoryRecordId: itemData.categoryId ?? null,
        isFavorite: itemData.isFavorite ?? false,
        sortOrder: null,
        totpSecret: itemData.totpSecret ?? null,
        totpIssuer: itemData.totpIssuer ?? null,
        totpLabel: itemData.totpLabel ?? null,
        totpAlgorithm: itemData.totpAlgorithm ?? null,
        totpDigits: itemData.totpDigits ?? null,
        totpPeriod: itemData.totpPeriod ?? null,
        customFields: null,
    };
}

function parseVerifiedOpLogPlaintext(record: LocalVerifiedRecord): Record<string, unknown> | null {
    if (
        (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
        || !record.plaintext
    ) {
        return null;
    }

    try {
        const parsed = JSON.parse(OPLOG_TEXT_DECODER.decode(record.plaintext)) as unknown;
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            ? parsed as Record<string, unknown>
            : null;
    } catch {
        return null;
    }
}

function getOptionalString(value: unknown): string | undefined {
    return typeof value === 'string' ? value : undefined;
}

function getOptionalBoolean(value: unknown): boolean | undefined {
    return typeof value === 'boolean' ? value : undefined;
}

export function VaultItemDialog({ open, onOpenChange, itemId, onSave, initialType = 'password' }: VaultItemDialogProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const {
        decryptItem,
        decryptData,
        opLogCreateItem,
        opLogUpdateItem,
        opLogDeleteItem,
        opLogLocalVaultState,
        verifyIntegrity,
        vaultMigrationStatus,
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
            if (vaultMigrationStatus === 'verified') {
                const opLogCategories = opLogLocalVaultState
                    ? Array.from(opLogLocalVaultState.recordsById.values()).flatMap((record) => {
                        if (record.record.recordType !== 'category') {
                            return [];
                        }
                        const plaintext = parseVerifiedOpLogPlaintext(record);
                        const name = getOptionalString(plaintext?.name);
                        if (!name) {
                            return [];
                        }
                        return [{
                            id: record.record.recordId,
                            name,
                            icon: getOptionalString(plaintext?.icon) ?? null,
                            color: getOptionalString(plaintext?.color) ?? null,
                        }];
                    })
                    : [];
                setCategories(opLogCategories);
                return;
            }

            const { snapshot, source } = await loadVaultSnapshot(user.id);
            if (shouldVerifyLegacyDialogCategorySnapshot(vaultMigrationStatus)) {
                const integrityResult = await verifyIntegrity(snapshot, { source });
                if (integrityResult?.mode === 'blocked') {
                    setCategories([]);
                    return;
                }
            }

            const resolvedCategories = await Promise.all(
                snapshot.categories.map(async (cat) => {
                    let resolvedName = cat.name;
                    let resolvedIcon = cat.icon;
                    let resolvedColor = cat.color;

                    if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedName = await decryptData(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category name:', cat.id, err);
                            resolvedName = 'Beschädigte Kategorie';
                        }
                    }

                    if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedIcon = await decryptData(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category icon:', cat.id, err);
                            resolvedIcon = null;
                        }
                    }

                    if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
                        try {
                            resolvedColor = await decryptData(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length));
                        } catch (err) {
                            console.error('Failed to decrypt category color:', cat.id, err);
                            resolvedColor = '#3b82f6';
                        }
                    }

                    return {
                        ...cat,
                        name: resolvedName,
                        icon: resolvedIcon,
                        color: resolvedColor,
                    };
                }),
            );

            setCategories(resolvedCategories);
        } catch (err) {
            console.error('Failed to load categories:', err);
            setCategories([]);
        }
    }, [user, open, decryptData, opLogLocalVaultState, verifyIntegrity, vaultMigrationStatus]);

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
                if (vaultMigrationStatus === 'verified') {
                    const record = opLogLocalVaultState?.recordsById.get(normalizedItemId) ?? null;
                    if (!record || record.record.recordType !== 'item') {
                        throw new Error('Item not found');
                    }

                    const plaintext = parseVerifiedOpLogPlaintext(record);
                    if (!plaintext) {
                        throw new Error('Item not verified');
                    }

                    const candidateType = getOptionalString(plaintext.itemType) ?? 'password';
                    const resolvedType: 'password' | 'note' | 'totp' =
                        candidateType === 'note'
                            ? 'note'
                            : candidateType === 'totp' && hasPremiumAuthenticator
                                ? 'totp'
                                : 'password';

                    form.reset({
                        title: getOptionalString(plaintext.title) ?? '',
                        url: getOptionalString(plaintext.websiteUrl) ?? '',
                        username: getOptionalString(plaintext.username) ?? '',
                        password: getOptionalString(plaintext.password) ?? '',
                        notes: getOptionalString(plaintext.notes) ?? '',
                        totpSecret: normalizeTOTPSecretInput(getOptionalString(plaintext.totpSecret) ?? ''),
                        totpIssuer: getOptionalString(plaintext.totpIssuer) ?? '',
                        totpLabel: getOptionalString(plaintext.totpLabel) ?? '',
                        totpAlgorithm: plaintext.totpAlgorithm === 'SHA256' || plaintext.totpAlgorithm === 'SHA512'
                            ? plaintext.totpAlgorithm
                            : DEFAULT_TOTP_ALGORITHM,
                        totpDigits: plaintext.totpDigits === 8 ? 8 : DEFAULT_TOTP_DIGITS,
                        totpPeriod: typeof plaintext.totpPeriod === 'number' ? plaintext.totpPeriod : DEFAULT_TOTP_PERIOD,
                        isFavorite: getOptionalBoolean(plaintext.isFavorite) ?? false,
                    });

                    setItemType(resolvedType);
                    setSelectedCategoryId(getOptionalString(plaintext.categoryRecordId) ?? null);
                    return;
                }

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
    }, [normalizedItemId, open, user, vaultMigrationStatus, opLogLocalVaultState, decryptItem, form, hasPremiumAuthenticator, toast, t]);

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

        setLoading(true);
        try {
            const itemData = buildVaultItemPayloadForEncryption(data, itemType, selectedCategoryId);
            const plaintext = buildOpLogItemPlaintext(itemData);
            const result = isEditing && normalizedItemId
                ? await opLogUpdateItem(normalizedItemId, plaintext)
                : await opLogCreateItem(plaintext);

            if (result.error) {
                throw result.error;
            }

            const savedRecordId = isEditing ? normalizedItemId : 'recordId' in result ? result.recordId : null;
            let pendingAttachmentFailureCount = 0;
            if (pendingAttachmentCount > 0) {
                if (savedRecordId && uploadPendingAttachmentsRef.current) {
                    try {
                        const uploadResult = await uploadPendingAttachmentsRef.current(savedRecordId);
                        pendingAttachmentFailureCount = uploadResult.failureCount;
                    } catch {
                        pendingAttachmentFailureCount = pendingAttachmentCount;
                    }
                } else {
                    pendingAttachmentFailureCount = pendingAttachmentCount;
                }
                setPendingAttachmentCount(0);
                uploadPendingAttachmentsRef.current = null;
            }

            toast({
                title: t('common.success'),
                description: isEditing ? t('vault.itemUpdated') : t('vault.itemCreated'),
            });

            if (pendingAttachmentFailureCount > 0) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('fileAttachments.pendingUploadFailed', {
                        count: pendingAttachmentFailureCount,
                        defaultValue: '{{count}} Dateianhang/Dateianhänge konnten nicht hochgeladen werden. Der Eintrag wurde ohne diese Anhänge gespeichert.',
                    }),
                });
            }

            clearSensitiveDialogState();
            onSave?.();
            onOpenChange(false);
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('vault.saveError'),
            });
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async () => {
        if (!normalizedItemId || !user) return;

        setDeleting(true);
        try {
            const result = await opLogDeleteItem(normalizedItemId);
            if (result.error) {
                throw result.error;
            }
            toast({
                title: t('common.success'),
                description: t('vault.itemDeleted'),
            });
            clearSensitiveDialogState();
            onSave?.();
            onOpenChange(false);
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('vault.deleteError'),
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
    const ItemTypeIcon = itemType === 'note' ? FileText : itemType === 'totp' ? Shield : Key;

    return (
        <>
            <Dialog open={open} onOpenChange={handleDialogOpenChange}>
                <DialogContent
                    className="max-h-[88vh] w-[calc(100vw-1.5rem)] overflow-hidden border border-border/60 bg-[linear-gradient(135deg,hsl(var(--card)/0.96),hsl(var(--el-1)/0.92))] p-0 shadow-[0_24px_70px_hsl(0_0%_0%/0.48)] backdrop-blur-2xl sm:max-w-2xl lg:max-w-4xl"
                    onOpenAutoFocus={(event) => {
                        // On mobile, Radix focusing the first input opens the keyboard immediately.
                        // Let the user decide whether they want to edit text or only adjust metadata.
                        event.preventDefault();
                    }}
                >
                    <div className="max-h-[88vh] overflow-y-auto">
                        <DialogHeader className="border-b border-border/45 px-5 py-4 sm:px-6">
                            <div className="flex items-start gap-3">
                                <div className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-primary/30 bg-primary/10 text-primary">
                                    <ItemTypeIcon className="h-5 w-5" aria-hidden="true" />
                                </div>
                                <div className="min-w-0">
                                    <DialogTitle className="text-xl">
                                        {isEditing ? t('vault.editItem') : t('vault.newItem')}
                                    </DialogTitle>
                                    <p className="mt-1 text-sm text-muted-foreground">
                                        {isEditing
                                            ? t('vault.form.entryDialogEditDescription', {
                                                defaultValue: 'Aktualisiere nur die Felder, die sich wirklich geändert haben.',
                                            })
                                            : t('vault.form.entryDialogCreateDescription', {
                                                defaultValue: 'Lege einen neuen Tresor-Eintrag mit klarer Kategorie und sicheren Metadaten an.',
                                            })}
                                    </p>
                                </div>
                            </div>
                        </DialogHeader>

                    {/* Item Type Tabs */}
                    {!isEditing && (
                        <Tabs
                            className="px-5 pt-5 sm:px-6"
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
                            <TabsList className="grid h-auto w-full grid-cols-2 rounded-lg border border-border/45 bg-background/45 p-1 sm:grid-cols-3">
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
                        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5 px-5 py-5 sm:px-6" autoComplete="off">
                            <div className="grid gap-5 lg:grid-cols-[minmax(0,1.08fr)_minmax(300px,0.82fr)]">
                                <div className="space-y-4 rounded-xl border border-border/45 bg-background/30 p-4 shadow-[inset_0_1px_0_hsl(var(--foreground)/0.04)]">
                                    <div>
                                        <h3 className="text-sm font-semibold text-foreground">
                                            {t('vault.form.primaryDetails', { defaultValue: 'Zugangsdaten' })}
                                        </h3>
                                        <p className="mt-1 text-xs leading-5 text-muted-foreground">
                                            {t('vault.form.primaryDetailsDescription', {
                                                defaultValue: 'Titel, Adresse und geheime Felder bleiben lokal entschlüsselt und werden erst beim Speichern signiert.',
                                            })}
                                        </p>
                                    </div>
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
                                    <div className="rounded-xl border border-primary/20 bg-[linear-gradient(135deg,hsl(var(--primary)/0.08),hsl(var(--el-2)/0.74))] p-4 shadow-[inset_0_1px_0_hsl(var(--foreground)/0.05)]">
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

                                </div>
                                <div className="space-y-4 rounded-xl border border-border/45 bg-background/30 p-4 shadow-[inset_0_1px_0_hsl(var(--foreground)/0.04)]">
                                    <div>
                                        <h3 className="text-sm font-semibold text-foreground">
                                            {t('vault.form.organization', { defaultValue: 'Organisation' })}
                                        </h3>
                                        <p className="mt-1 text-xs leading-5 text-muted-foreground">
                                            {t('vault.form.organizationDescription', {
                                                defaultValue: 'Notizen, Kategorie und Favorit steuern, wie der Eintrag im Tresor erscheint.',
                                            })}
                                        </p>
                                    </div>
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
                                    <FormItem className="flex items-center justify-between rounded-lg border border-border/35 bg-background/35 px-3 py-2.5">
                                        <div className="min-w-0">
                                            <FormLabel className="flex items-center gap-2">
                                                <Star className={cn('w-4 h-4', field.value && 'text-amber-500 fill-amber-500')} />
                                                {t('vault.fields.favorite')}
                                            </FormLabel>
                                            <p className="mt-0.5 text-xs text-muted-foreground">
                                                {t('vault.form.favoriteDescription', {
                                                    defaultValue: 'Markierte Einträge erscheinen schneller in der Übersicht.',
                                                })}
                                            </p>
                                        </div>
                                        <FormControl>
                                            <Switch
                                                checked={field.value}
                                                onCheckedChange={field.onChange}
                                            />
                                        </FormControl>
                                    </FormItem>
                                )}
                            />

                                </div>
                            </div>

                            {/* Actions */}
                            <div className="-mx-5 sticky bottom-0 flex flex-wrap items-center gap-2 border-t border-border/45 bg-background/85 px-5 pt-4 backdrop-blur-xl sm:-mx-6 sm:px-6">
                                {isEditing && (
                                    <Button
                                        type="button"
                                        variant="destructive"
                                        className="min-w-28"
                                        onClick={handleDelete}
                                        disabled={loading || deleting}
                                    >
                                        {deleting ? (
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        ) : (
                                            <Trash2 className="mr-2 h-4 w-4" />
                                        )}
                                        {t('common.delete')}
                                    </Button>
                                )}
                                <div className="flex-1" />
                                <Button
                                    type="button"
                                    variant="outline"
                                    className="min-w-28"
                                    onClick={() => onOpenChange(false)}
                                    disabled={loading}
                                >
                                    {t('common.cancel')}
                                </Button>
                                <Button type="submit" className="min-w-32 ms-header-primary-button" disabled={loading}>
                                    {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                                    {isEditing ? t('common.save') : t('common.create')}
                                </Button>
                            </div>
                        </form>
                    </Form>
                    </div>
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


