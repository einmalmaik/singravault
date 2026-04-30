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
import { Eye, KeyRound, Loader2, Plus, RefreshCw, Shield, TriangleAlert } from 'lucide-react';

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
import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { getServiceHooks } from '@/extensions/registry';
import { cn } from '@/lib/utils';
import { ItemFilter, ViewMode } from '@/pages/VaultPage';
import { isCurrentVaultItemEnvelope, VaultItemData } from '@/services/cryptoService';
import { isVaultItemEnvelopeV2 } from '@/services/vaultIntegrityV2/itemEnvelopeCrypto';
import {
  isAppOnline,
  loadVaultSnapshot,
} from '@/services/offlineVaultService';
import {
  LegacyVaultMetadataMigrationPersistenceError,
  migrateLegacyVaultItemEncryptionAndMetadata,
  migrateLegacyVaultItemMetadata,
} from '@/services/legacyVaultMetadataMigrationService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultItemCard } from './VaultItemCard';
import { VaultQuarantinedItemCard } from './VaultQuarantinedItemCard';
import { VaultQuarantinePanel } from './VaultQuarantinePanel';
import {
  VaultQuarantineRestoreProgressDialog,
  type VaultQuarantineRestoreProgressStatus,
} from './VaultQuarantineRestoreProgressDialog';

const DECRYPT_BATCH_SIZE = 25;
const QUARANTINE_SUMMARY_THRESHOLD = 2;

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

interface BulkRestoreProgress {
  open: boolean;
  status: VaultQuarantineRestoreProgressStatus;
  total: number;
  completed: number;
  failed: number;
  currentItemId: string | null;
  lastError: string | null;
}

function getQuarantineIgnoreToken(item: QuarantinedVaultItem): string {
  return `${item.reason}:${item.updatedAt ?? ''}`;
}

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
  const userId = user?.id ?? null;
  const {
    decryptItem,
    decryptItemForLegacyMigration,
    encryptItem,
    isDuressMode,
    lastIntegrityResult,
    quarantineResolutionById,
    reportUnreadableItems,
    refreshIntegrityBaseline,
    restoreQuarantinedItem,
    verifyIntegrity,
    vaultDataVersion,
  } = useVault();

  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const [ignoredQuarantineById, setIgnoredQuarantineById] = useState<Record<string, string>>({});
  const [showIgnoredQuarantine, setShowIgnoredQuarantine] = useState(false);
  const [bulkRestoreConfirmOpen, setBulkRestoreConfirmOpen] = useState(false);
  const [bulkRestoreProgress, setBulkRestoreProgress] = useState<BulkRestoreProgress>({
    open: false,
    status: 'running',
    total: 0,
    completed: 0,
    failed: 0,
    currentItemId: null,
    lastError: null,
  });
  const [revalidating, setRevalidating] = useState(false);
  const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
  const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());
  const revalidationRequestIdRef = useRef(0);
  const revalidatingRef = useRef(false);
  const fetchItemsRef = useRef(false);
  const pendingFetchItemsRef = useRef(false);
  const decryptItemRef = useRef(decryptItem);
  const decryptItemForLegacyMigrationRef = useRef(decryptItemForLegacyMigration);
  const encryptItemRef = useRef(encryptItem);
  const reportUnreadableItemsRef = useRef(reportUnreadableItems);
  const verifyIntegrityRef = useRef(verifyIntegrity);
  const refreshIntegrityBaselineRef = useRef(refreshIntegrityBaseline);

  useEffect(() => {
    decryptItemRef.current = decryptItem;
    decryptItemForLegacyMigrationRef.current = decryptItemForLegacyMigration;
    encryptItemRef.current = encryptItem;
    reportUnreadableItemsRef.current = reportUnreadableItems;
    verifyIntegrityRef.current = verifyIntegrity;
    refreshIntegrityBaselineRef.current = refreshIntegrityBaseline;
  }, [decryptItem, decryptItemForLegacyMigration, encryptItem, refreshIntegrityBaseline, reportUnreadableItems, verifyIntegrity]);

  useEffect(() => {
    failedDecryptPayloadByItemIdRef.current.clear();
    loggedDecryptFailuresRef.current.clear();
  }, [userId, isDuressMode]);

  const revalidateRemoteIntegrity = useCallback(async () => {
    if (!userId || revalidatingRef.current) {
      return;
    }

    const requestId = revalidationRequestIdRef.current + 1;
    revalidationRequestIdRef.current = requestId;
    revalidatingRef.current = true;
    setRevalidating(true);
    try {
      await verifyIntegrityRef.current();
    } finally {
      if (revalidationRequestIdRef.current === requestId) {
        revalidatingRef.current = false;
        setRevalidating(false);
      }
    }
  }, [userId]);

  useEffect(() => {
    async function fetchItems() {
      if (!userId) return;
      if (fetchItemsRef.current) {
        pendingFetchItemsRef.current = true;
        return;
      }

      fetchItemsRef.current = true;
      setLoading(true);
      try {
        const { snapshot, source } = await loadVaultSnapshot(userId);
        const integrityResult = await verifyIntegrityRef.current(snapshot, { source });
        if (integrityResult?.mode === 'blocked') {
          setItems([]);
          return;
        }
        const canPersistMigrations = integrityResult?.mode === 'healthy'
          && integrityResult.isFirstCheck
          && source === 'remote'
          && isAppOnline();
        const canPersistLegacyEncryptionMigration = source === 'remote'
          && isAppOnline()
          && (
            integrityResult?.mode === 'healthy'
            || (
              integrityResult?.mode === 'quarantine'
              && integrityResult.quarantinedItems.length > 0
              && integrityResult.quarantinedItems.every((item) => item.reason === 'decrypt_failed')
            )
          );

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

            let decryptedData: VaultItemData | null = null;
            try {
              decryptedData = await decryptItemRef.current(item.encrypted_data, item.id);
            } catch {
              if (canPersistLegacyEncryptionMigration) {
                let legacyMigrationDecrypt: Awaited<ReturnType<typeof decryptItemForLegacyMigrationRef.current>> | null = null;
                try {
                  legacyMigrationDecrypt = await decryptItemForLegacyMigrationRef.current(
                    item.encrypted_data,
                    item.id,
                  );
                  if (!legacyMigrationDecrypt.legacyNoAadFallbackUsed) {
                    throw new Error('No legacy encryption migration required.');
                  }
                } catch {
                  legacyMigrationDecrypt = null;
                }

                if (legacyMigrationDecrypt) {
                  try {
                    const migration = await migrateLegacyVaultItemEncryptionAndMetadata({
                      userId,
                      vaultId: snapshot.vaultId,
                      item,
                      decryptedData: legacyMigrationDecrypt.data,
                      canPersistRemote: true,
                      encryptItem: encryptItemRef.current,
                    });
                    integrityBaselineDirty = true;
                    trustedItemIds.add(item.id);
                    decryptableItemIds.add(item.id);
                    failedDecryptPayloadByItemIdRef.current.delete(item.id);

                    return {
                      ...migration.item,
                      decryptedData: migration.decryptedData,
                    };
                  } catch (migrationError) {
                    if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                      console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                      decryptableItemIds.add(item.id);
                      failedDecryptPayloadByItemIdRef.current.delete(item.id);
                      return {
                        ...item,
                        decryptedData: legacyMigrationDecrypt.data,
                      };
                    }
                    throw migrationError;
                  }
                }
              }

              failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
              unreadableItems.push({
                id: item.id,
                reason: 'decrypt_failed',
                updatedAt: item.updated_at ?? null,
                itemType: item.item_type ?? null,
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
            if (!decryptedData) {
              throw new Error('Vault item decrypt returned no data.');
            }

            decryptableItemIds.add(item.id);
            failedDecryptPayloadByItemIdRef.current.delete(item.id);

            const migration = await migrateLegacyVaultItemMetadata({
              userId,
              vaultId: snapshot.vaultId,
              item,
              decryptedData,
              canPersistRemote: canPersistMigrations,
              encryptItem: encryptItemRef.current,
            });
            if (migration.migrated) {
              integrityBaselineDirty = true;
              trustedItemIds.add(item.id);
            }

            const isCurrentOrV2Envelope = isVaultItemEnvelopeV2(migration.item.encrypted_data)
              || isCurrentVaultItemEnvelope(migration.item.encrypted_data);
            if (canPersistLegacyEncryptionMigration && !isCurrentOrV2Envelope) {
              try {
                const encryptionMigration = await migrateLegacyVaultItemEncryptionAndMetadata({
                  userId,
                  vaultId: snapshot.vaultId,
                  item: migration.item,
                  decryptedData: migration.decryptedData,
                  canPersistRemote: true,
                  encryptItem: encryptItemRef.current,
                });
                integrityBaselineDirty = true;
                trustedItemIds.add(item.id);
                decryptableItemIds.add(item.id);
                failedDecryptPayloadByItemIdRef.current.delete(item.id);

                return {
                  ...encryptionMigration.item,
                  decryptedData: encryptionMigration.decryptedData,
                };
              } catch (migrationError) {
                if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                  console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                  return {
                    ...migration.item,
                    decryptedData: migration.decryptedData,
                  };
                }
                throw migrationError;
              }
            }

            return {
              ...migration.item,
              decryptedData: migration.decryptedData,
            };
          },
        );

        reportUnreadableItemsRef.current(unreadableItems);

        const canPersistTrustedFirstBaseline = integrityResult?.mode === 'healthy'
          && integrityResult.isFirstCheck
          && source === 'remote'
          && isAppOnline()
          && unreadableItems.length === 0;

        if (
          (integrityBaselineDirty && (canPersistMigrations || canPersistLegacyEncryptionMigration))
          || canPersistTrustedFirstBaseline
        ) {
          await refreshIntegrityBaselineRef.current({
            itemIds: new Set([...decryptableItemIds, ...trustedItemIds]),
            categoryIds: snapshot.categories.map((category) => category.id),
          });
        }

        setItems(decryptedItems as VaultItem[]);

        // Cached snapshots keep the vault usable offline and while local writes
        // are pending. A lightweight remote revalidation follows so DB-side
        // tampering can move items into quarantine without waiting for edit/open.
        if (source !== 'remote' && isAppOnline()) {
          void revalidateRemoteIntegrity();
        }
      } catch (err) {
        console.error('Error fetching vault items:', err);
      } finally {
        fetchItemsRef.current = false;
        if (pendingFetchItemsRef.current) {
          pendingFetchItemsRef.current = false;
          void fetchItems();
          return;
        }
        setLoading(false);
        setDecrypting(false);
      }
    }

    void fetchItems();
  }, [
    refreshKey,
    isDuressMode,
    revalidateRemoteIntegrity,
    userId,
    vaultDataVersion,
  ]);

  const quarantinedItems = useMemo(
    () => lastIntegrityResult?.quarantinedItems ?? [],
    [lastIntegrityResult],
  );
  const quarantinedItemsById = useMemo(
    () => new Map(quarantinedItems.map((item) => [item.id, item])),
    [quarantinedItems],
  );
  const hasGroupedQuarantine = quarantinedItems.length >= QUARANTINE_SUMMARY_THRESHOLD;
  const canRenderGroupedQuarantine = filter === 'all' && !categoryId && searchQuery.trim() === '';
  const quarantineIgnoreStorageKey = user?.id
    ? `singra:vault-quarantine-ignored-items:${user.id}`
    : null;
  const activeIgnoredQuarantinedItems = useMemo(
    () => quarantinedItems.filter((item) => ignoredQuarantineById[item.id] === getQuarantineIgnoreToken(item)),
    [ignoredQuarantineById, quarantinedItems],
  );
  const activeIgnoredQuarantineIds = useMemo(
    () => new Set(activeIgnoredQuarantinedItems.map((item) => item.id)),
    [activeIgnoredQuarantinedItems],
  );
  const hasIgnoredGroupedQuarantine = hasGroupedQuarantine && activeIgnoredQuarantinedItems.length > 0;

  const canRenderInlineQuarantine = useCallback((
    item: VaultItem,
    quarantine: QuarantinedVaultItem,
  ) => {
    if (quarantinedItems.length !== 1 || searchQuery.trim() !== '') {
      return false;
    }

    const quarantinedItemType = quarantine.itemType ?? item.item_type;
    if (quarantinedItemType === 'totp') {
      return false;
    }

    if (categoryId && item.category_id !== categoryId) {
      return false;
    }

    if (filter === 'passwords') {
      return quarantinedItemType === 'password';
    }
    if (filter === 'notes') {
      return quarantinedItemType === 'note';
    }
    if (filter === 'favorites') {
      return false;
    }

    return filter === 'all';
  }, [filter, categoryId, searchQuery, quarantinedItems.length]);

  useEffect(() => {
    setShowIgnoredQuarantine(false);

    if (!quarantineIgnoreStorageKey || typeof window === 'undefined') {
      setIgnoredQuarantineById({});
      return;
    }

    try {
      const parsed = JSON.parse(window.localStorage.getItem(quarantineIgnoreStorageKey) || '{}');
      setIgnoredQuarantineById(
        parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? parsed as Record<string, string>
          : {},
      );
    } catch {
      setIgnoredQuarantineById({});
    }
  }, [quarantineIgnoreStorageKey]);

  const persistIgnoredQuarantine = useCallback((nextIgnoredById: Record<string, string>) => {
    if (!quarantineIgnoreStorageKey || typeof window === 'undefined') {
      return;
    }

    window.localStorage.setItem(quarantineIgnoreStorageKey, JSON.stringify(nextIgnoredById));
    setIgnoredQuarantineById(nextIgnoredById);
  }, [quarantineIgnoreStorageKey]);

  const handleIgnoreQuarantineItem = useCallback((item: QuarantinedVaultItem) => {
    persistIgnoredQuarantine({
      ...ignoredQuarantineById,
      [item.id]: getQuarantineIgnoreToken(item),
    });
  }, [ignoredQuarantineById, persistIgnoredQuarantine]);

  const visibleEntries = useMemo<RenderableVaultListEntry[]>(() => {
    return items.reduce<RenderableVaultListEntry[]>((entries, item) => {
      const quarantine = quarantinedItemsById.get(item.id);
      if (quarantine) {
        if (canRenderInlineQuarantine(item, quarantine)) {
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
    () => {
      if (!hasGroupedQuarantine || !canRenderGroupedQuarantine) {
        return [];
      }

      return quarantinedItems.filter(
        (item) => !inlineQuarantinedIds.has(item.id) && !activeIgnoredQuarantineIds.has(item.id),
      );
    },
    [
      activeIgnoredQuarantineIds,
      canRenderGroupedQuarantine,
      hasGroupedQuarantine,
      inlineQuarantinedIds,
      quarantinedItems,
    ],
  );
  const restorablePanelItems = useMemo(
    () => panelQuarantinedItems.filter(
      (item) => quarantineResolutionById[item.id]?.canRestore,
    ),
    [panelQuarantinedItems, quarantineResolutionById],
  );

  const handleIgnoreGroupedQuarantine = useCallback(() => {
    persistIgnoredQuarantine({
      ...ignoredQuarantineById,
      ...Object.fromEntries(
        panelQuarantinedItems.map((item) => [item.id, getQuarantineIgnoreToken(item)]),
      ),
    });
    setShowIgnoredQuarantine(false);
  }, [ignoredQuarantineById, panelQuarantinedItems, persistIgnoredQuarantine]);

  const handleRestoreAllVisible = useCallback(async () => {
    const itemsToRestore = restorablePanelItems;
    if (itemsToRestore.length === 0) {
      setBulkRestoreConfirmOpen(false);
      return;
    }

    setBulkRestoreConfirmOpen(false);
    setBulkRestoreProgress({
      open: true,
      status: 'running',
      total: itemsToRestore.length,
      completed: 0,
      failed: 0,
      currentItemId: itemsToRestore[0].id,
      lastError: null,
    });

    let completed = 0;
    let failed = 0;
    let lastError: string | null = null;

    for (const item of itemsToRestore) {
      setBulkRestoreProgress((current) => ({
        ...current,
        currentItemId: item.id,
      }));

      const result = await restoreQuarantinedItem(item.id);
      if (result.error) {
        failed += 1;
        lastError = result.error.message;
      } else {
        completed += 1;
      }

      setBulkRestoreProgress((current) => ({
        ...current,
        completed,
        failed,
        lastError,
      }));
    }

    setBulkRestoreProgress((current) => ({
      ...current,
      status: failed > 0 ? 'failed' : 'success',
      currentItemId: null,
      lastError,
    }));
  }, [restorablePanelItems, restoreQuarantinedItem]);

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
      {canRenderGroupedQuarantine && (hasGroupedQuarantine || revalidating) && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-[hsl(var(--border)/0.45)] bg-[hsl(var(--el-1))] px-4 py-3 text-sm">
          <p className="inline-flex items-center gap-2 text-muted-foreground">
            <RefreshCw className={cn('h-4 w-4', revalidating && 'animate-spin')} />
            {revalidating
              ? t('vault.integrity.revalidatingEntries', {
                defaultValue: 'Prüfe Einträge...',
              })
              : t('vault.integrity.revalidationHint', {
                defaultValue: 'Die Liste nutzt zuerst den lokalen Stand und prüft danach kurz gegen den Server.',
              })}
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={revalidating}
            onClick={() => void revalidateRemoteIntegrity()}
          >
            <RefreshCw className={cn('mr-2 h-4 w-4', revalidating && 'animate-spin')} />
            {t('vault.integrity.revalidateAction', {
              defaultValue: 'Tresor erneut prüfen',
            })}
          </Button>
        </div>
      )}

      {canRenderGroupedQuarantine && hasIgnoredGroupedQuarantine && !showIgnoredQuarantine && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm">
          <p className="inline-flex items-center gap-2 text-amber-800 dark:text-amber-200">
            <TriangleAlert className="h-4 w-4" />
            {t('vault.integrity.ignoredQuarantineHint', {
              defaultValue: '{{count}} manipulierte Einträge sind in der Quarantäne einsehbar.',
              count: activeIgnoredQuarantinedItems.length,
            })}
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="border-amber-500/35"
            onClick={() => setShowIgnoredQuarantine(true)}
          >
            <Eye className="mr-2 h-4 w-4" />
            {t('vault.integrity.showIgnoredQuarantineAction', {
              defaultValue: 'Quarantäne anzeigen',
            })}
          </Button>
        </div>
      )}

      <VaultQuarantinePanel
        items={panelQuarantinedItems}
        ignoredItems={showIgnoredQuarantine ? activeIgnoredQuarantinedItems : []}
        onIgnoreItem={handleIgnoreQuarantineItem}
        onRestoreAll={
          restorablePanelItems.length > 0
            ? () => setBulkRestoreConfirmOpen(true)
            : undefined
        }
        restoreAllCount={restorablePanelItems.length}
        restoreAllDisabled={bulkRestoreProgress.open && bulkRestoreProgress.status === 'running'}
        onIgnoreAll={
          hasGroupedQuarantine && canRenderGroupedQuarantine && panelQuarantinedItems.length > 0
            ? handleIgnoreGroupedQuarantine
            : undefined
        }
      />

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

      <AlertDialog
        open={bulkRestoreConfirmOpen}
        onOpenChange={setBulkRestoreConfirmOpen}
      >
        <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('vault.integrity.confirmBulkRestoreTitle', {
                defaultValue: '{{count}} Einträge wiederherstellen?',
                count: restorablePanelItems.length,
              })}
            </AlertDialogTitle>
            <AlertDialogDescription className="leading-relaxed">
              {t('vault.integrity.confirmBulkRestoreDescription', {
                defaultValue: 'Es werden nur Einträge wiederhergestellt, für die auf diesem Gerät eine vertrauenswürdige lokale Kopie verfügbar ist. Jeder Eintrag wird einzeln geprüft und danach verifiziert.',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('common.cancel', {
                defaultValue: 'Abbrechen',
              })}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleRestoreAllVisible();
              }}
            >
              {t('vault.integrity.confirmBulkRestoreAction', {
                defaultValue: 'Wiederherstellen',
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <VaultQuarantineRestoreProgressDialog
        open={bulkRestoreProgress.open}
        status={bulkRestoreProgress.status}
        total={bulkRestoreProgress.total}
        completed={bulkRestoreProgress.completed}
        failed={bulkRestoreProgress.failed}
        currentItemId={bulkRestoreProgress.currentItemId}
        lastError={bulkRestoreProgress.lastError}
        onContinue={() => {
          setBulkRestoreProgress((current) => ({
            ...current,
            open: false,
          }));
        }}
      />
    </div>
  );
}
