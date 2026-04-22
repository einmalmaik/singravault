// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Item List Component
 * 
 * Displays vault items in grid or list view with filtering,
 * search, and decryption.
 */

import { useMemo, useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, Plus, Shield, KeyRound } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { VaultItemCard } from './VaultItemCard';
import { ItemFilter, ViewMode } from '@/pages/VaultPage';
import { useVault } from '@/contexts/VaultContext';
import { supabase } from '@/integrations/supabase/client';
import { useAuth } from '@/contexts/AuthContext';
import { VaultItemData } from '@/services/cryptoService';
import { cn } from '@/lib/utils';
import { getServiceHooks } from '@/extensions/registry';
import {
    isAppOnline,
    loadVaultSnapshot,
    upsertOfflineItemRow,
} from '@/services/offlineVaultService';

const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';

interface VaultItem {
    id: string;
    vault_id: string;
    title: string;
    website_url: string | null;
    icon_url: string | null;
    item_type: 'password' | 'note' | 'totp' | 'card';
    is_favorite: boolean | null;
    category_id: string | null;
    created_at: string;
    updated_at: string;
    // Decrypted data
    decryptedData?: VaultItemData;
}

interface VaultItemListProps {
    searchQuery: string;
    filter: ItemFilter;
    categoryId: string | null;
    viewMode: ViewMode;
    onEditItem: (itemId: string) => void;
    refreshKey?: number; // Incremented to trigger data refresh
}

export function VaultItemList({
    searchQuery,
    filter,
    categoryId,
    viewMode,
    onEditItem,
    refreshKey,
}: VaultItemListProps) {
    const { t } = useTranslation();
    const { user } = useAuth();
    const { decryptItem, encryptItem, isDuressMode, refreshIntegrityBaseline } = useVault();

    const [items, setItems] = useState<VaultItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [decrypting, setDecrypting] = useState(false);
    const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
    const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());

    useEffect(() => {
        failedDecryptPayloadByItemIdRef.current.clear();
        loggedDecryptFailuresRef.current.clear();
    }, [user?.id, isDuressMode]);

    // Fetch vault items
    useEffect(() => {
        async function fetchItems() {
            if (!user) return;

            setLoading(true);
            try {
                const { snapshot, source } = await loadVaultSnapshot(user.id);
                const vaultItems = [...snapshot.items].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
                let integrityBaselineDirty = false;

                // Decrypt items
                setDecrypting(true);
                const decryptedItems = await Promise.all(
                    (vaultItems || []).map(async (item) => {
                        const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
                        if (cachedFailedPayload === item.encrypted_data) {
                            return { ...item, decryptedData: undefined };
                        }

                        try {
                            const decryptedData = await decryptItem(item.encrypted_data, item.id);
                            failedDecryptPayloadByItemIdRef.current.delete(item.id);
                            const hasLegacyPlaintextMeta =
                                (!decryptedData.title && item.title && item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER) ||
                                (!decryptedData.websiteUrl && !!item.website_url) ||
                                (!decryptedData.itemType && !!item.item_type) ||
                                (typeof decryptedData.isFavorite !== 'boolean' && item.is_favorite !== null) ||
                                (typeof decryptedData.categoryId === 'undefined' && item.category_id !== null);
                            const hasPlaintextColumnsToCleanup =
                                item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER ||
                                item.website_url !== null ||
                                item.icon_url !== null ||
                                item.item_type !== 'password' ||
                                !!item.is_favorite ||
                                item.category_id !== null;

                            if (hasLegacyPlaintextMeta || hasPlaintextColumnsToCleanup) {
                                const resolvedDecryptedData = {
                                    ...decryptedData,
                                    title: decryptedData.title || item.title,
                                    websiteUrl: decryptedData.websiteUrl || item.website_url || undefined,
                                    itemType: decryptedData.itemType || item.item_type || 'password',
                                    isFavorite: typeof decryptedData.isFavorite === 'boolean'
                                        ? decryptedData.isFavorite
                                        : !!item.is_favorite,
                                    categoryId: typeof decryptedData.categoryId !== 'undefined'
                                        ? decryptedData.categoryId
                                        : item.category_id,
                                };

                                if (source === 'remote' && isAppOnline()) {
                                    const migratedEncryptedData = await encryptItem(resolvedDecryptedData, item.id);

                                    await supabase
                                        .from('vault_items')
                                        .update({
                                            encrypted_data: migratedEncryptedData,
                                            title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                                            website_url: null,
                                            icon_url: null,
                                            item_type: 'password',
                                            is_favorite: false,
                                            category_id: null,
                                        })
                                        .eq('id', item.id);

                                    await upsertOfflineItemRow(user.id, {
                                        ...item,
                                        encrypted_data: migratedEncryptedData,
                                        title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                                        website_url: null,
                                        icon_url: null,
                                        item_type: 'password',
                                        is_favorite: false,
                                        category_id: null,
                                        updated_at: new Date().toISOString(),
                                    }, snapshot.vaultId);
                                    integrityBaselineDirty = true;
                                }

                                return {
                                    ...item,
                                    title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
                                    website_url: null,
                                    icon_url: null,
                                    item_type: 'password',
                                    is_favorite: false,
                                    category_id: null,
                                    decryptedData: resolvedDecryptedData,
                                };
                            }

                            return { ...item, decryptedData };
                        } catch (err) {
                            failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
                            const logKey = `${item.id}:${item.updated_at}`;
                            if (!loggedDecryptFailuresRef.current.has(logKey)) {
                                loggedDecryptFailuresRef.current.add(logKey);
                                console.debug(
                                    isDuressMode
                                        ? 'Failed to decrypt item in Duress Mode (expected for Real items):'
                                        : 'Failed to decrypt item (key mismatch or corrupt):',
                                    item.id
                                );
                            }
                            return { ...item, decryptedData: undefined };
                        }
                    })
                );

                if (integrityBaselineDirty) {
                    await refreshIntegrityBaseline();
                }

                setItems(decryptedItems as VaultItem[]);
            } catch (err) {
                console.error('Error fetching vault items:', err);
            } finally {
                setLoading(false);
                setDecrypting(false);
            }
        }

        fetchItems();
    }, [user, decryptItem, encryptItem, refreshKey, isDuressMode, refreshIntegrityBaseline]); // Added refreshKey to trigger refetch

    // Filter items
    const filteredItems = useMemo(() => {
        return items.filter((item) => {
            // Items that cannot be decrypted with the active key are never renderable.
            if (!item.decryptedData) return false;

            const resolvedCategoryId = item.decryptedData?.categoryId ?? item.category_id;
            const resolvedItemType = item.decryptedData?.itemType || item.item_type;
            const resolvedIsFavorite = typeof item.decryptedData?.isFavorite === 'boolean'
                ? item.decryptedData.isFavorite
                : !!item.is_favorite;

            // TOTP items belong exclusively in the Authenticator section — never shown here
            if (resolvedItemType === 'totp') return false;

            // Duress mode filter: only show decoy items in duress mode, real items otherwise
            // This is critical for plausible deniability — the filter happens AFTER decryption
            const hooks = getServiceHooks();
            const itemIsDecoy = hooks.isDecoyItem ? hooks.isDecoyItem(item.decryptedData as unknown as Record<string, unknown>) : false;
            if (isDuressMode && !itemIsDecoy) return false;
            if (!isDuressMode && itemIsDecoy) return false;

            // Category filter
            if (categoryId && resolvedCategoryId !== categoryId) return false;

            // Type filter
            if (filter === 'passwords' && resolvedItemType !== 'password') return false;
            if (filter === 'notes' && resolvedItemType !== 'note') return false;
            if (filter === 'favorites' && !resolvedIsFavorite) return false;

            // Search filter
            if (searchQuery) {
                const query = searchQuery.toLowerCase();
                const resolvedTitle = item.decryptedData?.title || item.title;
                const resolvedUrl = item.decryptedData?.websiteUrl || item.website_url;
                const matchTitle = resolvedTitle.toLowerCase().includes(query);
                const matchUrl = resolvedUrl?.toLowerCase().includes(query);
                const matchUsername = item.decryptedData?.username?.toLowerCase().includes(query);
                if (!matchTitle && !matchUrl && !matchUsername) return false;
            }

            return true;
        });
    }, [items, filter, categoryId, searchQuery, isDuressMode]);

    if (loading || decrypting) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-muted-foreground">
                <Loader2 className="w-8 h-8 animate-spin mb-4" />
                <p>{decrypting ? t('vault.items.decrypting') : t('common.loading')}</p>
            </div>
        );
    }

    if (items.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-center">
                <div className="p-4 rounded-full bg-[hsl(var(--el-2))] border border-[hsl(var(--border)/0.35)] mb-4">
                    <Shield className="w-8 h-8 text-primary/60" />
                </div>
                <h3 className="text-lg font-medium mb-2">{t('vault.empty.title')}</h3>
                <p className="text-muted-foreground mb-4 max-w-sm">
                    {t('vault.empty.description')}
                </p>
                <Button onClick={() => onEditItem('')}>
                    <Plus className="w-4 h-4 mr-2" />
                    {t('vault.empty.action')}
                </Button>
            </div>
        );
    }

    if (filteredItems.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center h-64 text-center">
                <div className="p-4 rounded-full bg-[hsl(var(--el-2))] border border-[hsl(var(--border)/0.35)] mb-4">
                    <KeyRound className="w-8 h-8 text-primary/60" />
                </div>
                <h3 className="text-lg font-medium mb-2">{t('vault.search.noResults')}</h3>
                <p className="text-muted-foreground max-w-sm">
                    {t('vault.search.noResultsDescription')}
                </p>
            </div>
        );
    }

    return (
        <div
            className={cn(
                viewMode === 'grid'
                    ? 'grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
                    : 'flex flex-col gap-2'
            )}
        >
            {filteredItems.map((item) => (
                <VaultItemCard
                    key={item.id}
                    item={item}
                    viewMode={viewMode}
                    onEdit={() => onEditItem(item.id)}
                />
            ))}
        </div>
    );
}
