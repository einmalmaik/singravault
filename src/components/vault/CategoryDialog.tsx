// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Category Dialog Component
 * 
 * Modal for creating and editing categories.
 * SVG icon input is blocked for security hardening.
 */

import { useState, useEffect } from 'react';
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
import { Textarea } from '@/components/ui/textarea';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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

import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { CategoryIcon } from './CategoryIcon';
import {
    buildCategoryRowFromInsert,
    buildVaultItemRowFromInsert,
    enqueueOfflineMutation,
    isAppOnline,
    isLikelyOfflineError,
    loadVaultSnapshot,
    removeOfflineCategoryRow,
    resolveDefaultVaultId,
    upsertOfflineCategoryRow,
    upsertOfflineItemRow,
} from '@/services/offlineVaultService';

// Common emojis for quick selection
const COMMON_EMOJIS = [
    '📱', '💼', '💳', '🛒', '🎮', '🏠', '✈️', '🎵',
    '📚', '🔧', '🏦', '💊', '🎬', '📧', '🔐', '⭐',
    '🌐', '💻', '📷', '🎨', '🏃', '🍔', '🚗', '📝',
];

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

interface CategoryDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    category: Category | null; // null = create new
    onSave?: () => void;
}

const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';

function isSvgPayload(value: string): boolean {
    const trimmed = value.trim();
    return trimmed.startsWith('<svg') || trimmed.startsWith('<?xml');
}

export function CategoryDialog({ open, onOpenChange, category, onSave }: CategoryDialogProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const { encryptData, decryptItem, encryptItem, refreshIntegrityBaseline } = useVault();

    const [name, setName] = useState('');
    const [icon, setIcon] = useState('');
    const [iconType, setIconType] = useState<'emoji' | 'svg'>('emoji');
    const [color, setColor] = useState<string>('#3b82f6');
    const [loading, setLoading] = useState(false);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

    const isEditing = !!category;

    // Load category data when editing
    useEffect(() => {
        if (category) {
            setName(category.name);
            const categoryIcon = category.icon || '';
            const legacySvgIcon = categoryIcon && isSvgPayload(categoryIcon);
            setIcon(legacySvgIcon ? '' : categoryIcon);
            setColor(category.color || '#3b82f6');
            setIconType('emoji');
        } else {
            setName('');
            setIcon('');
            setColor('#3b82f6');
            setIconType('emoji');
        }
    }, [category, open]);

    const handleSave = async () => {
        if (!user || !name.trim()) return;

        setLoading(true);
        try {
            let normalizedIcon: string | null = icon.trim() || null;

            if ((iconType === 'svg' && normalizedIcon) || (normalizedIcon && isSvgPayload(normalizedIcon))) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('categories.svgDisabled'),
                });
                return;
            }

            if (iconType === 'emoji' && normalizedIcon) {
                normalizedIcon = normalizedIcon.replace(/[<>]/g, '').slice(0, 4);
            }

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

            if (isAppOnline()) {
                try {
                    const { data: savedCategory, error } = await supabase
                        .from('categories')
                        .upsert(categoryData, { onConflict: 'id' })
                        .select('*')
                        .single();

                    if (error) throw error;
                    if (savedCategory) {
                        await upsertOfflineCategoryRow(user.id, savedCategory);
                    }
                    syncedOnline = true;
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            if (!syncedOnline) {
                await upsertOfflineCategoryRow(user.id, buildCategoryRowFromInsert(categoryData));
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
            onSave?.();
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

    const handleDelete = async () => {
        if (!category || !user) return;

        setLoading(true);
        try {
            const vaultId = await resolveDefaultVaultId(user.id);
            const { snapshot } = await loadVaultSnapshot(user.id);
            const items = vaultId
                ? snapshot.items.filter((item) => item.vault_id === vaultId)
                : snapshot.items;
            const trustedItemIds: string[] = [];

            for (const item of items) {
                try {
                    const decryptedData = await decryptItem(item.encrypted_data, item.id);
                    const resolvedCategoryId = decryptedData.categoryId ?? item.category_id ?? null;
                    if (resolvedCategoryId !== category.id) {
                        continue;
                    }

                    const migratedEncryptedData = await encryptItem({
                        ...decryptedData,
                        title: decryptedData.title || item.title,
                        websiteUrl: decryptedData.websiteUrl || item.website_url || undefined,
                        itemType: decryptedData.itemType || item.item_type || 'password',
                        isFavorite: typeof decryptedData.isFavorite === 'boolean'
                            ? decryptedData.isFavorite
                            : !!item.is_favorite,
                        categoryId: null,
                    }, item.id);

                    const itemPayload = {
                        id: item.id,
                        user_id: item.user_id,
                        vault_id: item.vault_id,
                        title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                        website_url: null,
                        icon_url: null,
                        item_type: 'password' as const,
                        is_favorite: false,
                        encrypted_data: migratedEncryptedData,
                        category_id: null,
                    };

                    let syncedItemOnline = false;
                    if (isAppOnline()) {
                        try {
                            const { data: savedItem, error } = await supabase
                                .from('vault_items')
                                .upsert(itemPayload, { onConflict: 'id' })
                                .select('*')
                                .single();
                            if (error) throw error;
                            if (savedItem) {
                                await upsertOfflineItemRow(user.id, savedItem, item.vault_id);
                            }
                            syncedItemOnline = true;
                        } catch (err) {
                            if (!isLikelyOfflineError(err)) {
                                throw err;
                            }
                        }
                    }

                    if (!syncedItemOnline) {
                        await upsertOfflineItemRow(user.id, buildVaultItemRowFromInsert(itemPayload), item.vault_id);
                        await enqueueOfflineMutation({
                            userId: user.id,
                            type: 'upsert_item',
                            payload: itemPayload,
                        });
                    }

                    trustedItemIds.push(item.id);
                } catch (err) {
                    console.error('Failed to unlink encrypted category reference:', item.id, err);
                }
            }

            if (isAppOnline()) {
                try {
                    await supabase
                        .from('vault_items')
                        .update({ category_id: null })
                        .eq('category_id', category.id);
                } catch (err) {
                    if (!isLikelyOfflineError(err)) {
                        throw err;
                    }
                }
            }

            let syncedCategoryDelete = false;
            if (isAppOnline()) {
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

            await removeOfflineCategoryRow(user.id, category.id);
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
                    ? t('categories.deleted')
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
            onSave?.();
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
                            <Tabs value={iconType} onValueChange={(v) => setIconType(v as 'emoji' | 'svg')}>
                                <TabsList className="w-full">
                                    <TabsTrigger value="emoji" className="flex-1">Emoji</TabsTrigger>
                                    <TabsTrigger value="svg" className="flex-1">SVG</TabsTrigger>
                                </TabsList>

                                <TabsContent value="emoji" className="space-y-2">
                                    {/* Quick emoji picker */}
                                    <div className="grid grid-cols-8 gap-1">
                                        {COMMON_EMOJIS.map((emoji) => (
                                            <button
                                                key={emoji}
                                                type="button"
                                                onClick={() => setIcon(emoji)}
                                                className={`p-2 text-lg rounded hover:bg-accent transition-colors ${icon === emoji ? 'bg-accent ring-2 ring-primary' : ''
                                                    }`}
                                            >
                                                {emoji}
                                            </button>
                                        ))}
                                    </div>
                                    <Input
                                        value={icon}
                                        onChange={(e) => setIcon(e.target.value)}
                                        placeholder={t('categories.emojiPlaceholder')}
                                        maxLength={4}
                                    />
                                </TabsContent>

                                <TabsContent value="svg" className="space-y-2">
                                    <Textarea
                                        value={icon}
                                        onChange={(e) => setIcon(e.target.value)}
                                        placeholder='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">...</svg>'
                                        className="font-mono text-xs h-24"
                                    />
                                    <p className="text-xs text-muted-foreground">
                                        {t('categories.svgHint')}
                                    </p>
                                </TabsContent>
                            </Tabs>
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
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>{t('categories.deleteConfirmTitle')}</AlertDialogTitle>
                        <AlertDialogDescription>
                            {t('categories.deleteConfirmDesc')}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>{t('common.cancel')}</AlertDialogCancel>
                        <AlertDialogAction onClick={handleDelete} className="bg-destructive text-destructive-foreground">
                            {t('common.delete')}
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>
        </>
    );
}

