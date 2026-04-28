// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Category Dialog Component
 * 
 * Modal for creating and editing categories.
 * SVG icon input is blocked for security hardening.
 */

import { useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Folder, Trash2, Palette } from 'lucide-react';

import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    AlertDialog,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';

import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { CategoryIcon } from './CategoryIcon';
import { CATEGORY_ICON_PRESETS, normalizeCategoryIcon } from './categoryIconPolicy';
import type { VaultItemData } from '@/services/cryptoService';
import {
    applyOfflineCategoryDeletion,
    buildCategoryRowFromInsert,
    buildVaultItemRowFromInsert,
    enqueueOfflineMutation,
    isAppOnline,
    isLikelyOfflineError,
    loadVaultSnapshot,
    shouldUseLocalOnlyVault,
    upsertOfflineCategoryRow,
} from '@/services/offlineVaultService';
import {
    ENCRYPTED_CATEGORY_PREFIX,
    neutralizeVaultItemServerMetadata,
} from '@/services/vaultMetadataPolicy';

// Preset colors
const PRESET_COLORS = [
    '#ef4444', '#f97316', '#eab308', '#22c55e',
    '#14b8a6', '#3b82f6', '#8b5cf6', '#ec4899',
];

interface Category {
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
}

export interface CategoryChangeEvent {
    type: 'saved' | 'deleted';
    categoryId: string;
}

interface CategoryDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    category: Category | null; // null = create new
    onSave?: (event?: CategoryChangeEvent) => void;
}

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];
type CategoryDeleteMode = 'unlink-items' | 'delete-items';

interface CategoryItemMatch {
    item: VaultItemRow;
    decryptedData: VaultItemData | null;
}

export function CategoryDialog({ open, onOpenChange, category, onSave }: CategoryDialogProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const { encryptData, decryptItem, encryptItem, refreshIntegrityBaseline } = useVault();

    const [name, setName] = useState('');
    const [icon, setIcon] = useState('');
    const [color, setColor] = useState<string>('#3b82f6');
    const [loading, setLoading] = useState(false);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [deleteImpactLoading, setDeleteImpactLoading] = useState(false);
    const [deleteImpactCount, setDeleteImpactCount] = useState<number | null>(null);

    const isEditing = !!category;

    // Load category data when editing
    useEffect(() => {
        if (category) {
            setName(category.name);
            setIcon(normalizeCategoryIcon(category.icon) ?? '');
            setColor(category.color || '#3b82f6');
        } else {
            setName('');
            setIcon('');
            setColor('#3b82f6');
        }
    }, [category, open]);

    const handleSave = async () => {
        if (!user || !name.trim()) return;

        setLoading(true);
        try {
            const canSyncOnline = !shouldUseLocalOnlyVault(user.id) && isAppOnline();
            const normalizedIcon = normalizeCategoryIcon(icon);

            const categoryId = isEditing ? category.id : crypto.randomUUID();
            const categoryData = {
                id: categoryId,
                name: `${ENCRYPTED_CATEGORY_PREFIX}${await encryptData(name.trim())}`,
                icon: normalizedIcon
                    ? `${ENCRYPTED_CATEGORY_PREFIX}${await encryptData(normalizedIcon)}`
                    : null,
                color: `${ENCRYPTED_CATEGORY_PREFIX}${await encryptData(color)}`,
                user_id: user.id,
                parent_id: null,
                sort_order: null,
            };

            let syncedOnline = false;
            let categoryRowForCache = buildCategoryRowFromInsert(categoryData);

            if (canSyncOnline) {
                try {
                    const { data: savedCategory, error } = await supabase
                        .from('categories')
                        .upsert(categoryData, { onConflict: 'id' })
                        .select('*')
                        .single();

                    if (error) throw error;
                    if (savedCategory) {
                        categoryRowForCache = savedCategory;
                    }
                    syncedOnline = true;
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            await upsertOfflineCategoryRow(user.id, categoryRowForCache);

            if (!syncedOnline) {
                await enqueueOfflineMutation({
                    userId: user.id,
                    type: 'upsert_category',
                    payload: categoryData,
                });
            }

            toast({
                title: t('common.success'),
                description: syncedOnline
                    ? (isEditing ? t('categories.updated') : t('categories.created'))
                    : t('vault.offlineSaved', {
                        defaultValue: 'Offline gespeichert. Wird bei Internet automatisch synchronisiert.',
                    }),
            });

            await refreshIntegrityBaseline({
                categoryIds: [categoryId],
            });

            onOpenChange(false);
            onSave?.({ type: 'saved', categoryId });
        } catch (err) {
            console.error('Error saving category:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('categories.saveFailed'),
            });
        } finally {
            setLoading(false);
        }
    };

    const loadItemsInCategory = useCallback(async (): Promise<CategoryItemMatch[]> => {
        if (!category || !user) return [];

        const { snapshot } = await loadVaultSnapshot(user.id);
        const items = snapshot.vaultId
            ? snapshot.items.filter((item) => item.vault_id === snapshot.vaultId)
            : snapshot.items;
        const matches: CategoryItemMatch[] = [];

        for (const item of items) {
            let decryptedData: VaultItemData | null = null;
            let resolvedCategoryId = item.category_id ?? null;

            try {
                decryptedData = await decryptItem(item.encrypted_data, item.id);
                resolvedCategoryId = decryptedData.categoryId ?? item.category_id ?? null;
            } catch (err) {
                if (item.category_id === category.id) {
                    console.warn('Could not decrypt item while checking category delete impact:', item.id, err);
                }
            }

            if (resolvedCategoryId === category.id) {
                matches.push({ item, decryptedData });
            }
        }

        return matches;
    }, [category, decryptItem, user]);

    useEffect(() => {
        if (!showDeleteConfirm || !category || !user) {
            setDeleteImpactCount(null);
            setDeleteImpactLoading(false);
            return;
        }

        let cancelled = false;
        setDeleteImpactLoading(true);
        setDeleteImpactCount(null);

        void loadItemsInCategory()
            .then((items) => {
                if (!cancelled) {
                    setDeleteImpactCount(items.length);
                }
            })
            .catch((err) => {
                if (!cancelled) {
                    console.error('Error checking category delete impact:', err);
                    setDeleteImpactCount(null);
                }
            })
            .finally(() => {
                if (!cancelled) {
                    setDeleteImpactLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };
    }, [category, loadItemsInCategory, showDeleteConfirm, user]);

    const handleDelete = async (mode: CategoryDeleteMode) => {
        if (!category || !user) return;

        setLoading(true);
        try {
            const canSyncOnline = !shouldUseLocalOnlyVault(user.id) && isAppOnline();
            const affectedItems = await loadItemsInCategory();
            const affectedItemIds = affectedItems.map(({ item }) => item.id);
            const updatedItemRows: VaultItemRow[] = [];
            const deletedItemIds: string[] = [];
            const trustedItemIds: string[] = [];

            if (mode === 'unlink-items') {
                for (const { item, decryptedData } of affectedItems) {
                    const itemData = decryptedData ?? {
                        title: item.title,
                        websiteUrl: item.website_url ?? undefined,
                        itemType: item.item_type,
                        isFavorite: !!item.is_favorite,
                    };
                    const migratedEncryptedData = await encryptItem({
                        ...itemData,
                        categoryId: null,
                    }, item.id);

                    const itemPayload = neutralizeVaultItemServerMetadata({
                        id: item.id,
                        user_id: item.user_id,
                        vault_id: item.vault_id,
                        encrypted_data: migratedEncryptedData,
                    });

                    let syncedItemOnline = false;
                    let itemRowForCache = buildVaultItemRowFromInsert(itemPayload);
                    if (canSyncOnline) {
                        try {
                            const { data: savedItem, error } = await supabase
                                .from('vault_items')
                                .upsert(itemPayload, { onConflict: 'id' })
                                .select('*')
                                .single();
                            if (error) throw error;
                            if (savedItem) {
                                itemRowForCache = savedItem;
                            }
                            syncedItemOnline = true;
                        } catch (err) {
                            if (!isLikelyOfflineError(err)) {
                                throw err;
                            }
                        }
                    }

                    updatedItemRows.push(itemRowForCache);

                    if (!syncedItemOnline) {
                        await enqueueOfflineMutation({
                            userId: user.id,
                            type: 'upsert_item',
                            payload: itemPayload,
                        });
                    }

                    trustedItemIds.push(item.id);
                }
            } else {
                for (const { item } of affectedItems) {
                    let syncedItemDelete = false;
                    if (canSyncOnline) {
                        try {
                            const { error } = await supabase
                                .from('vault_items')
                                .delete()
                                .eq('id', item.id);
                            if (error) throw error;
                            syncedItemDelete = true;
                        } catch (err) {
                            if (!isLikelyOfflineError(err)) {
                                throw err;
                            }
                        }
                    }

                    deletedItemIds.push(item.id);
                    if (!syncedItemDelete) {
                        await enqueueOfflineMutation({
                            userId: user.id,
                            type: 'delete_item',
                            payload: { id: item.id },
                        });
                    }
                    trustedItemIds.push(item.id);
                }
            }

            let syncedCategoryDelete = false;
            if (canSyncOnline) {
                try {
                    const { error } = await supabase
                        .from('categories')
                        .delete()
                        .eq('id', category.id);
                    if (error) throw error;
                    syncedCategoryDelete = true;
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            await applyOfflineCategoryDeletion(user.id, category.id, {
                updatedItems: updatedItemRows,
                deletedItemIds,
            });
            if (!syncedCategoryDelete) {
                await enqueueOfflineMutation({
                    userId: user.id,
                    type: 'delete_category',
                    payload: { id: category.id },
                });
            }

            toast({
                title: t('common.success'),
                description: syncedCategoryDelete
                    ? t(
                        mode === 'delete-items'
                            ? 'categories.deletedWithItems'
                            : 'categories.deletedOnlyCategory',
                        {
                            defaultValue: mode === 'delete-items'
                                ? 'Kategorie und {{count}} Einträge gelöscht.'
                                : 'Kategorie gelöscht. {{count}} Einträge bleiben ohne Kategorie.',
                            count: affectedItemIds.length,
                        },
                    )
                    : t('vault.offlineDeleteQueued', {
                        defaultValue: 'Offline gelöscht. Löschung wird bei Internet synchronisiert.',
                    }),
            });

            await refreshIntegrityBaseline({
                itemIds: trustedItemIds,
                categoryIds: [category.id],
            });

            setShowDeleteConfirm(false);
            onOpenChange(false);
            onSave?.({ type: 'deleted', categoryId: category.id });
        } catch (err) {
            console.error('Error deleting category:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('categories.deleteFailed'),
            });
        } finally {
            setLoading(false);
        }
    };

    const categoryDeleteItemCount = deleteImpactCount ?? 0;
    const categoryHasItems = categoryDeleteItemCount > 0;

    return (
        <>
            <Dialog open={open} onOpenChange={onOpenChange}>
                <DialogContent className="sm:max-w-md">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <Folder className="w-5 h-5" />
                            {isEditing ? t('categories.edit') : t('categories.add')}
                        </DialogTitle>
                        <DialogDescription>
                            {t('categories.description')}
                        </DialogDescription>
                    </DialogHeader>

                    <div className="space-y-4 py-4">
                        {/* Name Input */}
                        <div className="space-y-2">
                            <Label htmlFor="name">{t('categories.name')}</Label>
                            <Input
                                id="name"
                                value={name}
                                onChange={(e) => setName(e.target.value)}
                                placeholder={t('categories.namePlaceholder')}
                            />
                        </div>

                        {/* Icon Selection */}
                        <div className="space-y-2">
                            <Label>{t('categories.icon')}</Label>
                            <div className="grid grid-cols-8 gap-1">
                                <button
                                    type="button"
                                    onClick={() => setIcon('')}
                                    className={`p-2 text-lg rounded hover:bg-accent transition-colors ${icon === '' ? 'bg-accent ring-2 ring-primary' : ''
                                        }`}
                                    aria-label={t('categories.noIcon', { defaultValue: 'Kein Symbol' })}
                                >
                                    <Folder className="mx-auto h-5 w-5" />
                                </button>
                                {CATEGORY_ICON_PRESETS.map((emoji, index) => (
                                    <button
                                        key={`${emoji}-${index}`}
                                        type="button"
                                        onClick={() => setIcon(emoji)}
                                        className={`p-2 text-lg rounded hover:bg-accent transition-colors ${icon === emoji ? 'bg-accent ring-2 ring-primary' : ''
                                            }`}
                                    >
                                        {emoji}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Color Picker */}
                        <div className="space-y-2">
                            <Label className="flex items-center gap-2">
                                <Palette className="w-4 h-4" />
                                {t('categories.color')}
                            </Label>
                            <div className="flex items-center gap-2">
                                <div className="flex gap-1">
                                    {PRESET_COLORS.map((presetColor) => (
                                        <button
                                            key={presetColor}
                                            type="button"
                                            onClick={() => setColor(presetColor)}
                                            className={`w-6 h-6 rounded-full border-2 transition-transform ${color === presetColor
                                                ? 'border-foreground scale-110'
                                                : 'border-transparent hover:scale-105'
                                                }`}
                                            style={{ backgroundColor: presetColor }}
                                        />
                                    ))}
                                </div>
                                <Input
                                    type="color"
                                    value={color}
                                    onChange={(e) => setColor(e.target.value)}
                                    className="w-10 h-8 p-0 border-0"
                                />
                            </div>
                        </div>

                        {/* Preview */}
                        <div className="flex items-center gap-3 p-3 rounded-lg bg-muted">
                            <div
                                className="w-8 h-8 rounded flex items-center justify-center"
                                style={{ backgroundColor: color + '20' }}
                            >
                                <CategoryIcon icon={icon} className="w-5 h-5" />
                            </div>
                            <span className="font-medium">{name || t('categories.preview')}</span>
                        </div>
                    </div>

                    <DialogFooter className="flex gap-2">
                        {isEditing && (
                            <Button
                                variant="destructive"
                                onClick={() => setShowDeleteConfirm(true)}
                                disabled={loading}
                            >
                                <Trash2 className="w-4 h-4 mr-2" />
                                {t('common.delete')}
                            </Button>
                        )}
                        <div className="flex-1" />
                        <Button variant="outline" onClick={() => onOpenChange(false)}>
                            {t('common.cancel')}
                        </Button>
                        <Button onClick={handleSave} disabled={loading || !name.trim()}>
                            {loading ? t('common.loading') : t('common.save')}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            {/* Delete Confirmation */}
            <AlertDialog open={showDeleteConfirm} onOpenChange={setShowDeleteConfirm}>
                <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
                    <AlertDialogHeader>
                        <AlertDialogTitle className="break-words">{t('categories.deleteConfirmTitle')}</AlertDialogTitle>
                        <AlertDialogDescription className="break-words leading-relaxed">
                            {deleteImpactLoading
                                ? t('common.loading')
                                : categoryHasItems
                                    ? t('categories.deleteWithItemsDesc', {
                                        count: categoryDeleteItemCount,
                                        defaultValue: 'Diese Kategorie enthält {{count}} Einträge. Du kannst nur die Kategorie löschen oder die Einträge mitlöschen.',
                                    })
                                    : t('categories.deleteConfirmDesc')}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter className="gap-2 sm:flex-col-reverse sm:justify-start sm:space-x-0">
                        <AlertDialogCancel className="mt-0 h-auto min-h-10 w-full whitespace-normal break-words px-4 py-2 text-center leading-snug">
                            {t('common.cancel')}
                        </AlertDialogCancel>
                        {categoryHasItems && (
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => void handleDelete('unlink-items')}
                                disabled={loading || deleteImpactLoading}
                                className="h-auto min-h-10 w-full whitespace-normal break-words px-4 py-2 text-center leading-snug"
                            >
                                {t('categories.deleteCategoryOnly', {
                                    defaultValue: 'Nur Kategorie löschen',
                                })}
                            </Button>
                        )}
                        <Button
                            type="button"
                            variant="destructive"
                            onClick={() => void handleDelete(categoryHasItems ? 'delete-items' : 'unlink-items')}
                            disabled={loading || deleteImpactLoading}
                            className="h-auto min-h-10 w-full whitespace-normal break-words px-4 py-2 text-center leading-snug"
                        >
                            {categoryHasItems
                                ? t('categories.deleteCategoryAndItems', {
                                    defaultValue: 'Kategorie und Einträge löschen',
                                })
                                : t('common.delete')}
                        </Button>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </>
    );
}

