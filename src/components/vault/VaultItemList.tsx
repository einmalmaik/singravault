// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Component
 *
 * Displays vault items in grid or list view with filtering,
 * search, and decryption.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { KeyRound, Loader2, Plus, Shield } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { getServiceHooks } from '@/extensions/registry';
import { supabase } from '@/integrations/supabase/client';
import { cn } from '@/lib/utils';
import { ItemFilter, ViewMode } from '@/pages/VaultPage';
import { VaultItemData } from '@/services/cryptoService';
import {
  isAppOnline,
  loadVaultSnapshot,
  upsertOfflineItemRow,
} from '@/services/offlineVaultService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultItemCard } from './VaultItemCard';
import { VaultQuarantinedItemCard } from './VaultQuarantinedItemCard';
import { VaultQuarantinePanel } from './VaultQuarantinePanel';

const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';
const DECRYPT_BATCH_SIZE = 25;

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
  decryptedData?: VaultItemData;
}

interface VaultItemListProps {
  searchQuery: string;
  filter: ItemFilter;
  categoryId: string | null;
  viewMode: ViewMode;
  onEditItem: (itemId: string) => void;
  refreshKey?: number;
}

type RenderableVaultListEntry =
  | { kind: 'item'; item: VaultItem }
  | { kind: 'quarantined'; item: VaultItem; quarantine: QuarantinedVaultItem };

async function mapInBatches<TInput, TOutput>(
  items: TInput[],
  batchSize: number,
  mapper: (item: TInput) => Promise<TOutput>,
): Promise<TOutput[]> {
  const results: TOutput[] = [];

  for (let start = 0; start < items.length; start += batchSize) {
    const batch = items.slice(start, start + batchSize);
    results.push(...await Promise.all(batch.map(mapper)));

    if (start + batchSize < items.length) {
      await new Promise<void>((resolve) => {
        globalThis.setTimeout(resolve, 0);
      });
    }
  }

  return results;
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
  const {
    decryptItem,
    encryptItem,
    isDuressMode,
    lastIntegrityResult,
    reportUnreadableItems,
    refreshIntegrityBaseline,
    verifyIntegrity,
  } = useVault();

  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
  const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());

  useEffect(() => {
    failedDecryptPayloadByItemIdRef.current.clear();
    loggedDecryptFailuresRef.current.clear();
  }, [user?.id, isDuressMode]);

  useEffect(() => {
    async function fetchItems() {
      if (!user) return;

      setLoading(true);
      try {
        const { snapshot, source } = await loadVaultSnapshot(user.id);
        const integrityResult = await verifyIntegrity(snapshot);
        if (integrityResult?.mode === 'blocked') {
          setItems([]);
          return;
        }
        const canPersistMigrations = integrityResult?.mode === 'healthy'
          && integrityResult.isFirstCheck
          && source === 'remote'
          && isAppOnline();

        const vaultItems = [...snapshot.items].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
        let integrityBaselineDirty = false;
        const trustedItemIds = new Set<string>();
        const decryptableItemIds = new Set<string>();
        const unreadableItems: QuarantinedVaultItem[] = [];

        setDecrypting(true);
        const decryptedItems = await mapInBatches(
          vaultItems,
          DECRYPT_BATCH_SIZE,
          async (item) => {
            const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
            if (cachedFailedPayload === item.encrypted_data) {
              return { ...item, decryptedData: undefined };
            }

            try {
              const decryptedData = await decryptItem(item.encrypted_data, item.id);
              decryptableItemIds.add(item.id);
              failedDecryptPayloadByItemIdRef.current.delete(item.id);

              const hasLegacyPlaintextMeta =
                (!decryptedData.title && item.title && item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER)
                || (!decryptedData.websiteUrl && !!item.website_url)
                || (!decryptedData.itemType && !!item.item_type)
                || (typeof decryptedData.isFavorite !== 'boolean' && item.is_favorite !== null)
                || (typeof decryptedData.categoryId === 'undefined' && item.category_id !== null);
              const hasPlaintextColumnsToCleanup =
                item.title !== ENCRYPTED_ITEM_TITLE_PLACEHOLDER
                || item.website_url !== null
                || item.icon_url !== null
                || item.item_type !== 'password'
                || !!item.is_favorite
                || item.category_id !== null;

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

                if (canPersistMigrations) {
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
                  trustedItemIds.add(item.id);
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
            } catch {
              failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
              unreadableItems.push({
                id: item.id,
                reason: 'ciphertext_changed',
                updatedAt: item.updated_at ?? null,
              });
              const logKey = `${item.id}:${item.updated_at}`;
              if (!loggedDecryptFailuresRef.current.has(logKey)) {
                loggedDecryptFailuresRef.current.add(logKey);
                console.debug(
                  isDuressMode
                    ? 'Failed to decrypt item in Duress Mode (expected for Real items):'
                    : 'Failed to decrypt item (key mismatch or corrupt):',
                  item.id,
                );
              }

              return { ...item, decryptedData: undefined };
            }
          },
        );

        if (unreadableItems.length > 0) {
          reportUnreadableItems(unreadableItems);
        }

        const canPersistTrustedFirstBaseline = integrityResult?.mode === 'healthy'
          && integrityResult.isFirstCheck
          && source === 'remote'
          && isAppOnline()
          && unreadableItems.length === 0;

        if ((integrityBaselineDirty && canPersistMigrations) || canPersistTrustedFirstBaseline) {
          await refreshIntegrityBaseline({
            itemIds: new Set([...decryptableItemIds, ...trustedItemIds]),
            categoryIds: snapshot.categories.map((category) => category.id),
          });
        }

        setItems(decryptedItems as VaultItem[]);
      } catch (err) {
        console.error('Error fetching vault items:', err);
      } finally {
        setLoading(false);
        setDecrypting(false);
      }
    }

    void fetchItems();
  }, [
    user,
    decryptItem,
    encryptItem,
    refreshKey,
    isDuressMode,
    reportUnreadableItems,
    refreshIntegrityBaseline,
    verifyIntegrity,
  ]);

  const quarantinedItems = useMemo(
    () => lastIntegrityResult?.quarantinedItems ?? [],
    [lastIntegrityResult],
  );
  const quarantinedItemsById = useMemo(
    () => new Map(quarantinedItems.map((item) => [item.id, item])),
    [quarantinedItems],
  );

  const canRenderInlineQuarantine = useCallback(() => (
    filter === 'all'
    && !categoryId
    && searchQuery.trim() === ''
  ), [filter, categoryId, searchQuery]);

  const visibleEntries = useMemo<RenderableVaultListEntry[]>(() => {
    return items.reduce<RenderableVaultListEntry[]>((entries, item) => {
      const quarantine = quarantinedItemsById.get(item.id);
      if (quarantine) {
        if (canRenderInlineQuarantine()) {
          entries.push({ kind: 'quarantined', item, quarantine });
        }
        return entries;
      }

      if (!item.decryptedData) {
        return entries;
      }

      const resolvedCategoryId = item.decryptedData.categoryId ?? item.category_id;
      const resolvedItemType = item.decryptedData.itemType || item.item_type;
      const resolvedIsFavorite = typeof item.decryptedData.isFavorite === 'boolean'
        ? item.decryptedData.isFavorite
        : !!item.is_favorite;

      if (resolvedItemType === 'totp') {
        return entries;
      }

      const hooks = getServiceHooks();
      const itemIsDecoy = hooks.isDecoyItem
        ? hooks.isDecoyItem(item.decryptedData as unknown as Record<string, unknown>)
        : false;

      if (isDuressMode && !itemIsDecoy) {
        return entries;
      }
      if (!isDuressMode && itemIsDecoy) {
        return entries;
      }

      if (categoryId && resolvedCategoryId !== categoryId) {
        return entries;
      }

      if (filter === 'passwords' && resolvedItemType !== 'password') {
        return entries;
      }
      if (filter === 'notes' && resolvedItemType !== 'note') {
        return entries;
      }
      if (filter === 'favorites' && !resolvedIsFavorite) {
        return entries;
      }

      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const resolvedTitle = item.decryptedData.title || item.title;
        const resolvedUrl = item.decryptedData.websiteUrl || item.website_url;
        const matchTitle = resolvedTitle.toLowerCase().includes(query);
        const matchUrl = resolvedUrl?.toLowerCase().includes(query);
        const matchUsername = item.decryptedData.username?.toLowerCase().includes(query);
        if (!matchTitle && !matchUrl && !matchUsername) {
          return entries;
        }
      }

      entries.push({ kind: 'item', item });
      return entries;
    }, []);
  }, [
    items,
    quarantinedItemsById,
    canRenderInlineQuarantine,
    filter,
    categoryId,
    searchQuery,
    isDuressMode,
  ]);

  const inlineQuarantinedIds = useMemo(
    () => new Set(
      visibleEntries
        .filter((entry): entry is Extract<RenderableVaultListEntry, { kind: 'quarantined' }> => entry.kind === 'quarantined')
        .map((entry) => entry.quarantine.id),
    ),
    [visibleEntries],
  );

  const panelQuarantinedItems = useMemo(
    () => quarantinedItems.filter((item) => !inlineQuarantinedIds.has(item.id)),
    [inlineQuarantinedIds, quarantinedItems],
  );

  const renderableItemCount = items.filter((item) => item.decryptedData).length;

  if (loading || decrypting) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-muted-foreground">
        <Loader2 className="mb-4 h-8 w-8 animate-spin" />
        <p>{decrypting ? t('vault.items.decrypting') : t('common.loading')}</p>
      </div>
    );
  }

  if (items.length === 0 && quarantinedItems.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-center">
        <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
          <Shield className="h-8 w-8 text-primary/60" />
        </div>
        <h3 className="mb-2 text-lg font-medium">{t('vault.empty.title')}</h3>
        <p className="mb-4 max-w-sm text-muted-foreground">
          {t('vault.empty.description')}
        </p>
        <Button onClick={() => onEditItem('')}>
          <Plus className="mr-2 h-4 w-4" />
          {t('vault.empty.action')}
        </Button>
      </div>
    );
  }

  if (visibleEntries.length === 0 && quarantinedItems.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-center">
        <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
          <KeyRound className="h-8 w-8 text-primary/60" />
        </div>
        <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
        <p className="max-w-sm text-muted-foreground">
          {t('vault.search.noResultsDescription')}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <VaultQuarantinePanel items={panelQuarantinedItems} />

      {visibleEntries.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center text-center">
          <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
            <KeyRound className="h-8 w-8 text-primary/60" />
          </div>
          {renderableItemCount === 0 ? (
            <>
              <h3 className="mb-2 text-lg font-medium">
                {t('vault.integrity.onlyQuarantinedTitle', {
                  defaultValue: 'Derzeit sind nur Einträge in Quarantäne vorhanden',
                })}
              </h3>
              <p className="max-w-sm text-muted-foreground">
                {t('vault.integrity.onlyQuarantinedDescription', {
                  defaultValue: 'Normale Einträge sind aktuell nicht verfügbar. Prüfe die Quarantänehinweise oben.',
                })}
              </p>
            </>
          ) : (
            <>
              <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
              <p className="max-w-sm text-muted-foreground">
                {t('vault.search.noResultsDescription')}
              </p>
            </>
          )}
        </div>
      ) : (
        <div
          className={cn(
            viewMode === 'grid'
              ? 'grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
              : 'flex flex-col gap-2',
          )}
        >
          {visibleEntries.map((entry) => (
            entry.kind === 'item' ? (
              <VaultItemCard
                key={entry.item.id}
                item={entry.item}
                viewMode={viewMode}
                onEdit={() => onEditItem(entry.item.id)}
              />
            ) : (
              <VaultQuarantinedItemCard
                key={entry.quarantine.id}
                itemId={entry.quarantine.id}
                reason={entry.quarantine.reason}
                viewMode={viewMode}
              />
            )
          ))}
        </div>
      )}
    </div>
  );
}
