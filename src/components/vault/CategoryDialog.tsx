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

import type { Database } from '@/integrations/supabase/types';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { useToast } from '@/hooks/use-toast';
import { CategoryIcon } from './CategoryIcon';
import { CATEGORY_ICON_PRESETS, normalizeCategoryIcon } from './categoryIconPolicy';
import { getCategoryIconDefinition } from '@/lib/icons/categoryIconRegistry';
import type { VaultItemData } from '@/services/cryptoService';
import {
    loadVaultSnapshot,
} from '@/services/offlineVaultService';
import type { CategoryPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';

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
    initialAction?: 'delete';
    onSave?: (event?: CategoryChangeEvent) => void;
}

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];
type CategoryDeleteMode = 'unlink-items' | 'delete-items';

interface CategoryItemMatch {
    item: VaultItemRow;
    decryptedData: VaultItemData | null;
}

function parseVerifiedOpLogItemCategoryId(record: LocalVerifiedRecord): string | null {
    if (
        (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
        || record.record.recordType !== 'item'
        || !record.plaintext
    ) {
        return null;
    }

    try {
        const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return null;
        }

        const categoryRecordId = (parsed as Record<string, unknown>).categoryRecordId;
        return typeof categoryRecordId === 'string' ? categoryRecordId : null;
    } catch {
        return null;
    }
}

export function CategoryDialog({ open, onOpenChange, category, initialAction, onSave }: CategoryDialogProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const { user } = useAuth();
    const {
        decryptItem,
        opLogCreateCategory,
        opLogUpdateCategory,
        opLogDeleteCategory,
        opLogLocalVaultState,
        vaultMigrationStatus,
    } = useVault();

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

    useEffect(() => {
        if (open && category && initialAction === 'delete') {
            setShowDeleteConfirm(true);
        }
    }, [category, initialAction, open]);

    const handleSave = async () => {
        if (!user || !name.trim()) return;

        setLoading(true);
        try {
            const plaintext: CategoryPlaintext = {
                name: name.trim(),
                icon: normalizeCategoryIcon(icon),
                color,
                parentCategoryRecordId: null,
                sortOrder: null,
            };
            const result = isEditing
                ? await opLogUpdateCategory(category.id, plaintext)
                : await opLogCreateCategory(plaintext);
            if (result.error) {
                throw result.error;
            }

            const categoryId = isEditing
                ? category.id
                : 'recordId' in result ? result.recordId : null;
            toast({
                title: t('common.success'),
                description: t('categories.saved'),
            });
            onSave?.({ type: 'saved', categoryId: categoryId ?? category?.id ?? '' });
            onOpenChange(false);
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('categories.saveError'),
            });
        } finally {
            setLoading(false);
        }
    };

    const loadItemCountInCategory = useCallback(async (): Promise<number> => {
        if (!category || !user) return 0;

        if (vaultMigrationStatus === 'verified') {
            if (!opLogLocalVaultState) {
                return 0;
            }

            let count = 0;
            for (const record of opLogLocalVaultState.recordsById.values()) {
                if (parseVerifiedOpLogItemCategoryId(record) === category.id) {
                    count += 1;
                }
            }

            return count;
        }

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

        return matches.length;
    }, [category, decryptItem, opLogLocalVaultState, user, vaultMigrationStatus]);

    useEffect(() => {
        if (!showDeleteConfirm || !category || !user) {
            setDeleteImpactCount(null);
            setDeleteImpactLoading(false);
            return;
        }

        let cancelled = false;
        setDeleteImpactLoading(true);
        setDeleteImpactCount(null);

        void loadItemCountInCategory()
            .then((count) => {
                if (!cancelled) {
                    setDeleteImpactCount(count);
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
    }, [category, loadItemCountInCategory, showDeleteConfirm, user]);

    const handleDelete = async (mode: CategoryDeleteMode) => {
        if (!category || !user) return;

        setLoading(true);
        try {
            const result = await opLogDeleteCategory(
                category.id,
                mode === 'delete-items' ? 'deleteItems' : 'unlinkItems',
            );
            if (result.error) {
                throw result.error;
            }

            toast({
                title: t('common.success'),
                description: t('categories.deleted'),
            });
            onSave?.({ type: 'deleted', categoryId: category.id });
            setShowDeleteConfirm(false);
            onOpenChange(false);
        } catch (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: error instanceof Error ? error.message : t('categories.deleteError'),
            });
        } finally {
            setLoading(false);
        }
    };

    const categoryDeleteItemCount = deleteImpactCount ?? 0;
    const categoryHasItems = categoryDeleteItemCount > 0;

    return (
        <>
            {/* Edit dialog — must NOT open when the caller wants immediate delete confirmation */}
            <Dialog open={open && !(category && initialAction === 'delete')} onOpenChange={onOpenChange}>
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
                            <div className="max-h-[11.5rem] overflow-y-auto rounded-lg border border-border/45 bg-background/35 p-2">
                            <div className="grid grid-cols-5 gap-1 sm:grid-cols-8">
                                <button
                                    type="button"
                                    onClick={() => setIcon('')}
                                    className={`p-2 text-lg rounded hover:bg-accent transition-colors ${icon === '' ? 'bg-accent ring-2 ring-primary' : ''
                                        }`}
                                    aria-label={t('categories.noIcon', { defaultValue: 'Kein Symbol' })}
                                >
                                    <Folder className="mx-auto h-5 w-5" />
                                </button>
                                {CATEGORY_ICON_PRESETS.map((categoryIconId) => {
                                    const definition = getCategoryIconDefinition(categoryIconId);
                                    const PresetIcon = definition.Icon;
                                    return (
                                    <button
                                        key={categoryIconId}
                                        type="button"
                                        onClick={() => setIcon(categoryIconId)}
                                        className={`p-2 text-lg rounded hover:bg-accent transition-colors ${icon === categoryIconId ? 'bg-accent ring-2 ring-primary' : ''
                                            }`}
                                        aria-label={definition.label}
                                        title={definition.label}
                                    >
                                        <PresetIcon className="mx-auto h-5 w-5" aria-hidden="true" />
                                    </button>
                                    );
                                })}
                            </div>
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
            <AlertDialog
                open={showDeleteConfirm}
                onOpenChange={(open) => {
                    setShowDeleteConfirm(open);
                    // When the AlertDialog closes without an action, close the whole CategoryDialog too.
                    if (!open) {
                        onOpenChange(false);
                    }
                }}
            >
                <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
                    <AlertDialogHeader>
                        <AlertDialogTitle className="break-words">{t('categories.deleteConfirmTitle')}</AlertDialogTitle>
                        <AlertDialogDescription className="break-words leading-relaxed">
                            {deleteImpactLoading
                                ? t('common.loading')
                                : categoryHasItems
                                    ? t('categories.deleteWithItemsOptionsDesc', {
                                        count: categoryDeleteItemCount,
                                        defaultValue: 'Diese Kategorie enthält {{count}} Eintrag/Einträge. Wähle, ob die Einträge behalten oder ebenfalls gelöscht werden.',
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

