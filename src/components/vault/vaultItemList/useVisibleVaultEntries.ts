// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Visible Vault Entries Hook
 *
 * Single-responsibility filtering layer between raw vault items and the UI:
 * applies search, category, type, favorite and OpLog-egress filters and
 * decides whether a quarantined item should render inline or move into the
 * grouped panel above the list.
 *
 * Also derives dashboard groupings (favorites, recently used, per-category,
 * uncategorized) so the render code in `VaultItemList.tsx` stays declarative.
 *
 * Security notes:
 * - Honours `opLogVerifiedItemIds`: when defined, items not in the verified
 *   set are hidden from the list and search so locked/quarantined vault modes
 *   never leak content.
 * - Duress and decoy filtering preserves the existing invariant: decoy items
 *   are only visible in duress mode, real items only outside duress mode.
 */

import { useCallback, useMemo } from 'react';

import { getServiceHooks } from '@/extensions/registry';
import type { ItemFilter } from '@/pages/VaultPage';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';

import type { CategorySummary } from './vaultItemPlaintextMapper';
import {
  getItemCategoryId,
  type RenderableVaultItemEntry,
  type RenderableVaultListEntry,
  type VaultItem,
} from './vaultItemModel';

const QUARANTINE_SUMMARY_THRESHOLD = 2;
const RECENT_SECTION_LIMIT = 8;

export interface UseVisibleVaultEntriesInput {
  readonly items: readonly VaultItem[];
  readonly searchQuery: string;
  readonly filter: ItemFilter;
  readonly categoryId: string | null;
  readonly isDuressMode: boolean;
  readonly quarantinedItems: readonly QuarantinedVaultItem[];
  readonly categorySummaries: readonly CategorySummary[];
  readonly opLogVerifiedItemIds: ReadonlySet<string> | null;
  readonly recentlyCopiedItemIds: readonly string[];
}

export interface UseVisibleVaultEntriesResult {
  readonly visibleEntries: RenderableVaultListEntry[];
  readonly visibleItemEntries: RenderableVaultItemEntry[];
  readonly favoriteEntries: RenderableVaultItemEntry[];
  readonly recentlyUsedEntries: RenderableVaultItemEntry[];
  readonly groupedCategorySections: { category: CategorySummary; entries: RenderableVaultItemEntry[] }[];
  readonly uncategorizedEntries: RenderableVaultItemEntry[];
  readonly inlineQuarantinedIds: Set<string>;
  readonly hasGroupedQuarantine: boolean;
  readonly canRenderGroupedQuarantine: boolean;
}

export function useVisibleVaultEntries({
  items,
  searchQuery,
  filter,
  categoryId,
  isDuressMode,
  quarantinedItems,
  categorySummaries,
  opLogVerifiedItemIds,
  recentlyCopiedItemIds,
}: UseVisibleVaultEntriesInput): UseVisibleVaultEntriesResult {
  const quarantinedItemsById = useMemo(
    () => new Map(quarantinedItems.map((item) => [item.id, item])),
    [quarantinedItems],
  );

  const hasGroupedQuarantine = quarantinedItems.length >= QUARANTINE_SUMMARY_THRESHOLD;
  const canRenderGroupedQuarantine = filter === 'all' && !categoryId && searchQuery.trim() === '';

  // A single quarantine event is rendered inline next to its sibling items
  // when no search/category filter is active and the type matches the
  // current type filter. Anything beyond that goes to the grouped panel so
  // we never silently hide multiple incidents.
  const canRenderInlineQuarantine = useCallback((
    item: VaultItem,
    quarantine: QuarantinedVaultItem,
  ): boolean => {
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

      // Phase 10: when OpLog UI is active, exclude non-verified records from search results.
      if (opLogVerifiedItemIds && !opLogVerifiedItemIds.has(item.id)) {
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
    opLogVerifiedItemIds,
  ]);

  const visibleItemEntries = useMemo(
    () => visibleEntries.filter(
      (entry): entry is RenderableVaultItemEntry => entry.kind === 'item',
    ),
    [visibleEntries],
  );

  const favoriteEntries = useMemo(
    () => visibleItemEntries
      .filter(({ item }) => item.decryptedData?.isFavorite ?? item.is_favorite),
    [visibleItemEntries],
  );

  const recentlyUsedEntries = useMemo(() => {
    const byId = new Map(visibleItemEntries.map((entry) => [entry.item.id, entry]));
    const explicitRecentEntries = recentlyCopiedItemIds
      .map((id) => byId.get(id))
      .filter((entry): entry is RenderableVaultItemEntry => !!entry);
    const explicitRecentIds = new Set(explicitRecentEntries.map((entry) => entry.item.id));

    const fallbackEntries = [...visibleItemEntries]
      .filter((entry) => !explicitRecentIds.has(entry.item.id))
      .sort((left, right) => right.item.updated_at.localeCompare(left.item.updated_at))
      .slice(0, RECENT_SECTION_LIMIT - explicitRecentEntries.length);

    return [...explicitRecentEntries, ...fallbackEntries].slice(0, RECENT_SECTION_LIMIT);
  }, [recentlyCopiedItemIds, visibleItemEntries]);

  const groupedCategorySections = useMemo(() => (
    categorySummaries
      .map((category) => ({
        category,
        entries: visibleItemEntries.filter((entry) => getItemCategoryId(entry.item) === category.id),
      }))
      .filter((section) => section.entries.length > 0)
  ), [categorySummaries, visibleItemEntries]);

  const uncategorizedEntries = useMemo(() => (
    visibleItemEntries.filter((entry) => !getItemCategoryId(entry.item))
  ), [visibleItemEntries]);

  const inlineQuarantinedIds = useMemo(
    () => new Set(
      visibleEntries
        .filter((entry): entry is Extract<RenderableVaultListEntry, { kind: 'quarantined' }> => entry.kind === 'quarantined')
        .map((entry) => entry.quarantine.id),
    ),
    [visibleEntries],
  );

  return {
    visibleEntries,
    visibleItemEntries,
    favoriteEntries,
    recentlyUsedEntries,
    groupedCategorySections,
    uncategorizedEntries,
    inlineQuarantinedIds,
    hasGroupedQuarantine,
    canRenderGroupedQuarantine,
  };
}
