// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Component
 *
 * Composes the vault item list view:
 *  - read pipeline (snapshot/OpLog decryption + cloud sync) — `useVaultItemListData`
 *  - derived groupings (favorites, recent, per-category) — `useVisibleVaultEntries`
 *  - write paths (move/favorite/delete) — `useVaultItemMutations`
 *  - focus highlight scroll-to-row — `useVaultItemFocusHighlight`
 *  - pointer-event drag, ignored quarantine, bulk restore — dedicated hooks
 *  - user-facing chrome — small components under `./vaultItemList`
 *
 * This file is intentionally a thin composition: every non-trivial concern
 * lives in a focused, individually testable module.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, TriangleAlert } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';
import { ItemFilter, ViewMode } from '@/pages/VaultPage';
import { writeClipboard } from '@/services/clipboardService';
import { getVerifiedRecordIdsForEgress } from '@/services/vaultOpLog';
import { useToast } from '@/hooks/use-toast';

import { VaultItemListSyncBar } from './vaultItemList/VaultItemListSyncBar';
import {
  VaultItemListEmptyVault,
  VaultItemListEmptyVisible,
  VaultItemListLoadingState,
  VaultItemListNoSearchResults,
} from './vaultItemList/VaultItemListEmptyStates';
import { VaultItemListCardRow } from './vaultItemList/VaultItemListCardRow';
import { VaultItemListDashboard } from './vaultItemList/VaultItemListDashboard';
import { VaultItemListPreviewPanel } from './vaultItemList/VaultItemListPreviewPanel';
import { VaultItemListBulkRestoreDialogs } from './vaultItemList/VaultItemListBulkRestoreDialogs';
import { useVaultItemListData } from './vaultItemList/useVaultItemListData';
import { useVisibleVaultEntries } from './vaultItemList/useVisibleVaultEntries';
import { useVaultIgnoredQuarantine } from './vaultItemList/useVaultIgnoredQuarantine';
import {
  scrollViewportForDrag,
  useVaultItemPointerDrag,
} from './vaultItemList/useVaultItemPointerDrag';
import { useVaultItemMutations } from './vaultItemList/useVaultItemMutations';
import { useVaultItemFocusHighlight } from './vaultItemList/useVaultItemFocusHighlight';
import { useVaultBulkRestore } from './vaultItemList/useVaultBulkRestore';
import type { VaultItemListRowApi } from './vaultItemList/vaultItemListRowApi';
import type { VaultItem } from './vaultItemList/vaultItemModel';
import {
  parseOpLogCategoryPlaintext,
  type CategorySummary,
} from './vaultItemList/vaultItemPlaintextMapper';
import { VaultQuarantinePanel } from './VaultQuarantinePanel';
import { VaultQuarantinedItemCard } from './VaultQuarantinedItemCard';

interface VaultItemListProps {
  searchQuery: string;
  filter: ItemFilter;
  categoryId: string | null;
  viewMode: ViewMode;
  onEditItem: (itemId: string) => void;
  refreshKey?: number;
  securityStatusLoading?: boolean;
  focusItemId?: string | null;
}

export function VaultItemList({
  searchQuery,
  filter,
  categoryId,
  viewMode,
  onEditItem,
  refreshKey,
  securityStatusLoading = false,
  focusItemId = null,
}: VaultItemListProps) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const {
    decryptItem,
    decryptItemForLegacyMigration,
    duressDecoyItems,
    encryptItem,
    isDuressMode,
    lastIntegrityResult,
    opLogRestoreRecord,
    quarantineResolutionById,
    reportUnreadableItems,
    refreshIntegrityBaseline,
    verifyIntegrity,
    vaultDataVersion,
    vaultMigrationStatus,
    opLogLocalVaultState,
    opLogUpdateItem,
    opLogUiRefresh,
    opLogUiView,
    opLogDeleteItem,
  } = useVault();
  const useOpLogVerifiedRuntime = vaultMigrationStatus === 'verified';

  const {
    items,
    setItems,
    loading,
    decrypting,
    backgroundSyncing,
    lastCloudSyncAt,
    revalidating,
    revalidateRemoteIntegrity,
  } = useVaultItemListData({
    userId,
    isDuressMode,
    duressDecoyItems,
    useOpLogVerifiedRuntime,
    opLogLocalVaultState,
    refreshKey,
    vaultDataVersion,
    decryptItem,
    decryptItemForLegacyMigration,
    encryptItem,
    reportUnreadableItems,
    verifyIntegrity,
    refreshIntegrityBaseline,
    opLogUiRefresh,
  });

  // Local view state. Lives in the main component because more than one
  // sub-tree consumes it (preview, sync indicators, drag state).
  const [recentlyCopiedItemIds, setRecentlyCopiedItemIds] = useState<string[]>([]);
  const [dropTargetCategoryId, setDropTargetCategoryId] = useState<string | null>(null);
  const [nativeDraggingItemId, setNativeDraggingItemId] = useState<string | null>(null);
  const [previewItemId, setPreviewItemId] = useState<string | null>(null);
  const [deletePreviewItemId, setDeletePreviewItemId] = useState<string | null>(null);
  const [deletingPreviewItem, setDeletingPreviewItem] = useState(false);

  // Native HTML5 drag is global; wire the auto-scroll listener only while a
  // drag is active so we do not run on every mouse move outside drag mode.
  useEffect(() => {
    if (!nativeDraggingItemId) {
      return undefined;
    }

    const handleDragOver = (event: DragEvent) => {
      scrollViewportForDrag(event.clientY);
    };

    window.addEventListener('dragover', handleDragOver);
    return () => window.removeEventListener('dragover', handleDragOver);
  }, [nativeDraggingItemId]);

  const quarantinedItems = useMemo(
    () => lastIntegrityResult?.quarantinedItems ?? [],
    [lastIntegrityResult],
  );

  const {
    activeIgnoredQuarantinedItems,
    activeIgnoredQuarantineIds,
    showIgnoredQuarantine,
    setShowIgnoredQuarantine,
    ignoreItem: handleIgnoreQuarantineItem,
    ignoreItems: persistIgnoredQuarantineItems,
  } = useVaultIgnoredQuarantine({ userId, quarantinedItems });

  // Phase 10: in OpLog runtime only verified items may be searched. When the
  // vault security mode is lockedCritical/safeMode/safeModeRecommended,
  // `getVerifiedRecordIdsForEgress` returns an empty set and hides everything.
  const opLogVerifiedItemIds = useMemo(
    () => getVerifiedRecordIdsForEgress(opLogUiView),
    [opLogUiView],
  );

  const categorySummaries = useMemo<CategorySummary[]>(() => {
    if (!opLogLocalVaultState) {
      return [];
    }

    return Array.from(opLogLocalVaultState.recordsById.values())
      .map(parseOpLogCategoryPlaintext)
      .filter((category): category is CategorySummary => !!category)
      .sort((left, right) => left.name.localeCompare(right.name, 'de'));
  }, [opLogLocalVaultState]);

  const categoryNameById = useMemo(
    () => new Map(categorySummaries.map((category) => [category.id, category.name])),
    [categorySummaries],
  );

  const {
    visibleEntries,
    visibleItemEntries,
    favoriteEntries,
    recentlyUsedEntries,
    groupedCategorySections,
    uncategorizedEntries,
    inlineQuarantinedIds,
    hasGroupedQuarantine,
    canRenderGroupedQuarantine,
  } = useVisibleVaultEntries({
    items,
    searchQuery,
    filter,
    categoryId,
    isDuressMode,
    quarantinedItems,
    categorySummaries,
    opLogVerifiedItemIds,
    recentlyCopiedItemIds,
  });

  const markItemRecentlyUsed = useCallback((itemId: string) => {
    setRecentlyCopiedItemIds((current) => [
      itemId,
      ...current.filter((id) => id !== itemId),
    ].slice(0, 20));
  }, []);

  const showOpError = useCallback((message: string) => {
    toast({ variant: 'destructive', title: t('common.error'), description: message });
  }, [t, toast]);

  const showFavoriteCooldown = useCallback((remainingSeconds: number) => {
    toast({
      title: t('vault.favoriteCooldown.title', { defaultValue: 'Bitte kurz warten' }),
      description: t('vault.favoriteCooldown.description', {
        defaultValue: 'Favoriten werden gerade verschlüsselt gespeichert. Du kannst in {{count}} Sekunden weitermachen.',
        count: remainingSeconds,
      }),
    });
  }, [t, toast]);

  const {
    moveItemToCategory,
    toggleItemFavorite,
    deleteItem,
  } = useVaultItemMutations({
    items,
    setItems,
    opLogLocalVaultState,
    opLogUpdateItem,
    opLogDeleteItem,
    onMarkRecentlyUsed: markItemRecentlyUsed,
    onError: showOpError,
    onFavoriteCooldown: showFavoriteCooldown,
  });

  const pointerDrag = useVaultItemPointerDrag({
    onMoveItemToCategory: moveItemToCategory,
    onDropTargetChange: setDropTargetCategoryId,
  });

  const openItemPreview = useCallback((item: VaultItem) => {
    markItemRecentlyUsed(item.id);
    setPreviewItemId(item.id);
  }, [markItemRecentlyUsed]);

  const editItemFromPreview = useCallback((itemId: string) => {
    markItemRecentlyUsed(itemId);
    setPreviewItemId(null);
    onEditItem(itemId);
  }, [markItemRecentlyUsed, onEditItem]);

  const copySecretFromRow = useCallback(async (
    item: VaultItem,
    value: string | null | undefined,
    type: 'Username' | 'Password',
  ) => {
    if (!value || (opLogVerifiedItemIds !== null && !opLogVerifiedItemIds.has(item.id))) {
      return;
    }

    try {
      await writeClipboard(value);
      markItemRecentlyUsed(item.id);
      toast({
        title: t('vault.copied'),
        description: `${t(`vault.copied${type}`)} ${t('vault.clipboardAutoClear')}`,
      });
    } catch {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('vault.copyFailed'),
      });
    }
  }, [markItemRecentlyUsed, opLogVerifiedItemIds, t, toast]);

  const previewItem = useMemo(
    () => visibleItemEntries.find((entry) => entry.item.id === previewItemId)?.item ?? null,
    [previewItemId, visibleItemEntries],
  );

  const deletePreviewItem = useMemo(
    () => visibleItemEntries.find((entry) => entry.item.id === deletePreviewItemId)?.item ?? null,
    [deletePreviewItemId, visibleItemEntries],
  );

  useEffect(() => {
    if (previewItemId && !visibleItemEntries.some((entry) => entry.item.id === previewItemId)) {
      setPreviewItemId(null);
    }
  }, [previewItemId, visibleItemEntries]);

  const handleFocusVisible = useCallback((itemId: string) => {
    markItemRecentlyUsed(itemId);
    setPreviewItemId(itemId);
  }, [markItemRecentlyUsed]);

  const { highlightedItemId, registerElement } = useVaultItemFocusHighlight({
    focusItemId,
    visibleItemEntries,
    onFocusVisible: handleFocusVisible,
  });

  const confirmDeletePreviewItem = useCallback(async () => {
    if (!deletePreviewItem) {
      return;
    }

    setDeletingPreviewItem(true);
    const result = await deleteItem(deletePreviewItem.id);
    setDeletingPreviewItem(false);

    if (!result.ok) {
      return;
    }

    setDeletePreviewItemId(null);
    setPreviewItemId(null);
    toast({
      title: t('common.success'),
      description: t('vault.itemDeleted'),
    });
  }, [deleteItem, deletePreviewItem, t, toast]);

  const panelQuarantinedItems = useMemo(() => {
    if (!hasGroupedQuarantine || !canRenderGroupedQuarantine) {
      return [];
    }
    return quarantinedItems.filter(
      (item) => !inlineQuarantinedIds.has(item.id) && !activeIgnoredQuarantineIds.has(item.id),
    );
  }, [
    activeIgnoredQuarantineIds,
    canRenderGroupedQuarantine,
    hasGroupedQuarantine,
    inlineQuarantinedIds,
    quarantinedItems,
  ]);

  const restorablePanelItems = useMemo(
    () => panelQuarantinedItems.filter((item) => quarantineResolutionById[item.id]?.canRestore),
    [panelQuarantinedItems, quarantineResolutionById],
  );

  const handleIgnoreGroupedQuarantine = useCallback(() => {
    persistIgnoredQuarantineItems(panelQuarantinedItems);
    setShowIgnoredQuarantine(false);
  }, [panelQuarantinedItems, persistIgnoredQuarantineItems, setShowIgnoredQuarantine]);

  const bulkRestore = useVaultBulkRestore({ opLogRestoreRecord });

  const handleCategoryDrop = useCallback((nextCategoryId: string, itemId: string) => {
    setNativeDraggingItemId(null);
    void moveItemToCategory(itemId, nextCategoryId);
  }, [moveItemToCategory]);

  const rowApi = useMemo<VaultItemListRowApi>(() => ({
    highlightedItemId,
    canCopySecrets: (itemId) =>
      opLogVerifiedItemIds === null || opLogVerifiedItemIds.has(itemId),
    registerElement,
    onNativeDragStart: setNativeDraggingItemId,
    onNativeDragEnd: () => {
      setNativeDraggingItemId(null);
      setDropTargetCategoryId(null);
    },
    onMarkRecentlyUsed: markItemRecentlyUsed,
    onOpenPreview: openItemPreview,
    onEditFromPreview: editItemFromPreview,
    onToggleFavorite: (item) => { void toggleItemFavorite(item); },
    onCopyUsername: (item, value) => { void copySecretFromRow(item, value, 'Username'); },
    onCopyPassword: (item, value) => { void copySecretFromRow(item, value, 'Password'); },
    pointerDrag: {
      start: pointerDrag.startPointerDrag,
      move: pointerDrag.handlePointerDragMove,
      complete: pointerDrag.completePointerDrag,
      cancel: pointerDrag.cancelPointerDrag,
    },
  }), [
    copySecretFromRow,
    editItemFromPreview,
    highlightedItemId,
    markItemRecentlyUsed,
    openItemPreview,
    opLogVerifiedItemIds,
    pointerDrag.cancelPointerDrag,
    pointerDrag.completePointerDrag,
    pointerDrag.handlePointerDragMove,
    pointerDrag.startPointerDrag,
    registerElement,
    toggleItemFavorite,
  ]);

  const renderableItemCount = items.filter((item) => item.decryptedData).length;
  const hasIgnoredGroupedQuarantine = hasGroupedQuarantine && activeIgnoredQuarantinedItems.length > 0;
  const shouldRenderDashboardSections =
    viewMode === 'grid'
    && filter === 'all'
    && !categoryId
    && searchQuery.trim() === ''
    && visibleItemEntries.length > 1;

  if ((loading || decrypting) && items.length === 0 && quarantinedItems.length === 0) {
    return <VaultItemListLoadingState decrypting={decrypting} />;
  }

  if (items.length === 0 && quarantinedItems.length === 0) {
    return <VaultItemListEmptyVault onAddItem={() => onEditItem('')} />;
  }

  if (visibleEntries.length === 0 && quarantinedItems.length === 0) {
    return <VaultItemListNoSearchResults />;
  }

  return (
    <div className="space-y-4">
      <VaultItemListSyncBar
        backgroundSyncing={backgroundSyncing}
        lastCloudSyncAt={lastCloudSyncAt}
        securityStatusLoading={securityStatusLoading}
        showRevalidationButton={canRenderGroupedQuarantine && (hasGroupedQuarantine || revalidating)}
        revalidating={revalidating}
        onRevalidate={() => void revalidateRemoteIntegrity()}
      />

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
            ? () => bulkRestore.setConfirmOpen(true)
            : undefined
        }
        restoreAllCount={restorablePanelItems.length}
        restoreAllDisabled={bulkRestore.progress.open && bulkRestore.progress.status === 'running'}
        onIgnoreAll={
          hasGroupedQuarantine && canRenderGroupedQuarantine && panelQuarantinedItems.length > 0
            ? handleIgnoreGroupedQuarantine
            : undefined
        }
      />

      {visibleEntries.length === 0 ? (
        <VaultItemListEmptyVisible hasAnyDecryptableItem={renderableItemCount > 0} />
      ) : shouldRenderDashboardSections ? (
        <VaultItemListDashboard
          viewMode={viewMode}
          api={rowApi}
          favoriteEntries={favoriteEntries}
          recentlyUsedEntries={recentlyUsedEntries}
          groupedCategorySections={groupedCategorySections}
          uncategorizedEntries={uncategorizedEntries}
          visibleItemCount={visibleItemEntries.length}
          categoryNameById={categoryNameById}
          dropTargetCategoryId={dropTargetCategoryId}
          onDropTargetChange={setDropTargetCategoryId}
          onCategoryDrop={handleCategoryDrop}
        />
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
              <VaultItemListCardRow
                key={entry.item.id}
                entry={entry}
                viewMode={viewMode}
                api={rowApi}
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

      {pointerDrag.pointerDrag?.active && (
        <div
          className="pointer-events-none fixed z-[90] max-w-[min(280px,calc(100vw-2rem))] rounded-lg border border-primary/40 bg-background/90 px-3 py-2 text-sm font-medium text-foreground shadow-[0_18px_52px_hsl(0_0%_0%/0.45)] backdrop-blur-xl"
          style={{
            left: (Number.isFinite(pointerDrag.pointerDrag.x) ? pointerDrag.pointerDrag.x : 0) + 12,
            top: (Number.isFinite(pointerDrag.pointerDrag.y) ? pointerDrag.pointerDrag.y : 0) + 12,
          }}
        >
          <span className="block truncate">{pointerDrag.pointerDrag.title}</span>
          <span className="text-xs text-primary">
            {t('vault.dragDrop.moving', { defaultValue: 'Verschieben' })}
          </span>
        </div>
      )}

      <VaultItemListPreviewPanel
        previewItem={previewItem}
        deletePreviewItem={deletePreviewItem}
        deletingPreviewItem={deletingPreviewItem}
        canCopySecrets={previewItem ? rowApi.canCopySecrets(previewItem.id) : false}
        onClose={() => {
          setDeletePreviewItemId(null);
          setPreviewItemId(null);
        }}
        onCopyUsername={(item) => rowApi.onCopyUsername(item, item.decryptedData?.username ?? null)}
        onCopyPassword={(item) => rowApi.onCopyPassword(item, item.decryptedData?.password ?? null)}
        onToggleFavorite={rowApi.onToggleFavorite}
        onEdit={rowApi.onEditFromPreview}
        onRequestDelete={setDeletePreviewItemId}
        onCancelDelete={() => setDeletePreviewItemId(null)}
        onConfirmDelete={() => void confirmDeletePreviewItem()}
      />

      <VaultItemListBulkRestoreDialogs
        confirmOpen={bulkRestore.confirmOpen}
        onConfirmOpenChange={bulkRestore.setConfirmOpen}
        restorableCount={restorablePanelItems.length}
        onConfirmRestoreAll={() => void bulkRestore.restoreAll(restorablePanelItems)}
        progress={bulkRestore.progress}
        onProgressContinue={bulkRestore.closeProgress}
      />
    </div>
  );
}
