// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Dashboard
 *
 * The grouped "Alle Einträge" view used when no search/filter is active.
 * Composes three sections in order:
 *  1. Favorites carousel (cards)
 *  2. Recently used (table)
 *  3. Categorised + uncategorised tables, with category drop targets
 *
 * Owns purely-presentational state (favorite expansion + collapsed
 * categories) and the cross-list drop target highlight. All vault mutations
 * (toggle favorite, copy, category move) are delegated to the parent through
 * the row API + `onCategoryDrop` callback.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ChevronDown, ChevronRight, Clock3, Pin } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

import {
  useFavoriteScrollerDrag,
} from './useFavoriteScrollerDrag';
import { VaultItemListCardRow } from './VaultItemListCardRow';
import { VaultItemListTableRow } from './VaultItemListTableRow';
import type { CategorySummary } from './vaultItemPlaintextMapper';
import type { RenderableVaultItemEntry } from './vaultItemModel';
import { VAULT_ITEM_DRAG_MIME, type VaultItemListRowApi } from './vaultItemListRowApi';
import type { ViewMode } from '@/pages/VaultPage';

const FAVORITE_COLLAPSED_LIMIT_MOBILE = 4;
const FAVORITE_COLLAPSED_LIMIT_DESKTOP = 6;
const SUPPRESSED_TOGGLE_GRACE_MS = 500;

interface VaultItemListDashboardProps {
  readonly viewMode: ViewMode;
  readonly api: VaultItemListRowApi;
  readonly favoriteEntries: readonly RenderableVaultItemEntry[];
  readonly recentlyUsedEntries: readonly RenderableVaultItemEntry[];
  readonly groupedCategorySections: ReadonlyArray<{
    category: CategorySummary;
    entries: readonly RenderableVaultItemEntry[];
  }>;
  readonly uncategorizedEntries: readonly RenderableVaultItemEntry[];
  readonly visibleItemCount: number;
  readonly categoryNameById: ReadonlyMap<string, string>;
  readonly dropTargetCategoryId: string | null;
  readonly onDropTargetChange: (categoryId: string | null) => void;
  readonly onCategoryDrop: (categoryId: string, itemId: string) => void;
}

export function VaultItemListDashboard({
  viewMode,
  api,
  favoriteEntries,
  recentlyUsedEntries,
  groupedCategorySections,
  uncategorizedEntries,
  visibleItemCount,
  categoryNameById,
  dropTargetCategoryId,
  onDropTargetChange,
  onCategoryDrop,
}: VaultItemListDashboardProps) {
  const { t } = useTranslation();
  const favoriteScroller = useFavoriteScrollerDrag();

  const [favoriteExpanded, setFavoriteExpanded] = useState(false);
  const [favoriteCollapsedLimit, setFavoriteCollapsedLimit] = useState(FAVORITE_COLLAPSED_LIMIT_DESKTOP);
  const [collapsedCategoryIds, setCollapsedCategoryIds] = useState<Set<string>>(() => new Set());

  // Same drop event also triggers the category header toggle button click;
  // remember the drop so the toggle stays "closed" instead of immediately
  // expanding the freshly-targeted category section.
  const suppressedCategoryToggleRef = useRef<{ categoryId: string; until: number } | null>(null);

  useEffect(() => {
    const updateFavoriteLimit = () => {
      setFavoriteCollapsedLimit(
        window.innerWidth < 768
          ? FAVORITE_COLLAPSED_LIMIT_MOBILE
          : FAVORITE_COLLAPSED_LIMIT_DESKTOP,
      );
    };

    updateFavoriteLimit();
    window.addEventListener('resize', updateFavoriteLimit);
    return () => window.removeEventListener('resize', updateFavoriteLimit);
  }, []);

  const toggleCategoryCollapsed = useCallback((categoryId: string) => {
    setCollapsedCategoryIds((current) => {
      const next = new Set(current);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  }, []);

  const consumeSuppressedCategoryToggle = useCallback((categoryId: string): boolean => {
    const suppressed = suppressedCategoryToggleRef.current;
    if (!suppressed) {
      return false;
    }
    if (suppressed.until < Date.now()) {
      suppressedCategoryToggleRef.current = null;
      return false;
    }
    if (suppressed.categoryId !== categoryId) {
      return false;
    }
    suppressedCategoryToggleRef.current = null;
    return true;
  }, []);

  const getDraggedVaultItemId = useCallback((event: React.DragEvent): string => (
    event.dataTransfer.getData(VAULT_ITEM_DRAG_MIME)
    || event.dataTransfer.getData('text/plain')
  ), []);

  const handleCategoryDrop = useCallback((categoryId: string, event: React.DragEvent) => {
    event.preventDefault();
    event.stopPropagation();
    suppressedCategoryToggleRef.current = {
      categoryId,
      until: Date.now() + SUPPRESSED_TOGGLE_GRACE_MS,
    };
    onDropTargetChange(null);
    api.onNativeDragEnd();
    const itemId = getDraggedVaultItemId(event);
    if (!itemId) {
      return;
    }
    onCategoryDrop(categoryId, itemId);
  }, [api, getDraggedVaultItemId, onCategoryDrop, onDropTargetChange]);

  const tableHeader = useMemo(() => (
    <div className="hidden grid-cols-[minmax(210px,1.3fr)_minmax(120px,0.9fr)_minmax(110px,0.8fr)_minmax(110px,0.8fr)_132px] gap-3 px-3 py-2 text-[11px] font-medium uppercase tracking-[0.08em] text-muted-foreground md:grid">
      <span>{t('vault.table.name', { defaultValue: 'Name' })}</span>
      <span>{t('vault.table.username', { defaultValue: 'Benutzername' })}</span>
      <span>{t('vault.table.password', { defaultValue: 'Passwort' })}</span>
      <span>{t('vault.table.lastUsed', { defaultValue: 'Zuletzt verwendet' })}</span>
      <span className="text-right">{t('vault.table.actions', { defaultValue: 'Aktionen' })}</span>
    </div>
  ), [t]);

  const hasCategorizedEntries = groupedCategorySections.length > 0;
  const hasUncategorizedEntries = uncategorizedEntries.length > 0;
  const hasFavorites = favoriteEntries.length > 0;
  const hasRecent = recentlyUsedEntries.length > 0;
  const showAllEntriesSection = hasCategorizedEntries || hasUncategorizedEntries;

  return (
    <div className="space-y-7">
      {hasFavorites && (
        <FavoritesSection
          entries={favoriteEntries}
          collapsedLimit={favoriteCollapsedLimit}
          expanded={favoriteExpanded}
          onToggleExpanded={() => setFavoriteExpanded((value) => !value)}
          viewMode={viewMode}
          api={api}
          scrollerRef={favoriteScroller.scrollerRef}
          onPointerDown={favoriteScroller.onPointerDown}
          onPointerMove={favoriteScroller.onPointerMove}
          onPointerEnd={favoriteScroller.onPointerEnd}
        />
      )}

      {hasRecent && (
        <RecentSection
          entries={recentlyUsedEntries}
          api={api}
          categoryNameById={categoryNameById}
          showTopBorder={hasFavorites}
        />
      )}

      {showAllEntriesSection && (
        <section className={cn(
          'space-y-4',
          (hasFavorites || hasRecent) && 'border-t border-border/35 pt-5',
        )}>
          <div className="flex items-center justify-between gap-3 px-1">
            <h2 className="text-sm font-semibold text-foreground">
              {t('vault.sections.allEntries', { defaultValue: 'Alle Einträge' })}
            </h2>
            <span className="text-xs text-muted-foreground">
              {t('vault.sections.entryCount', {
                defaultValue: '{{count}} Einträge',
                count: visibleItemCount,
              })}
            </span>
          </div>

          {groupedCategorySections.map(({ category, entries }) => {
            const collapsed = collapsedCategoryIds.has(category.id);
            const isDropTarget = dropTargetCategoryId === category.id;

            return (
              <div
                key={category.id}
                data-vault-category-drop-id={category.id}
                className={cn(
                  'overflow-hidden rounded-xl border border-[hsl(var(--border)/0.32)] bg-[hsl(var(--el-1)/0.72)] backdrop-blur transition-colors',
                  isDropTarget && 'border-primary/70 ring-2 ring-primary/30',
                )}
                onDragEnter={(event) => {
                  event.preventDefault();
                  event.dataTransfer.dropEffect = 'move';
                  onDropTargetChange(category.id);
                }}
                onDragOver={(event) => {
                  event.preventDefault();
                  event.dataTransfer.dropEffect = 'move';
                  onDropTargetChange(category.id);
                }}
                onDragLeave={() => {
                  if (dropTargetCategoryId === category.id) {
                    onDropTargetChange(null);
                  }
                }}
                onDrop={(event) => handleCategoryDrop(category.id, event)}
              >
                <button
                  type="button"
                  className="flex w-full items-center justify-between gap-3 px-3 py-3 text-left transition-colors hover:bg-white/[0.035]"
                  onClick={() => {
                    if (consumeSuppressedCategoryToggle(category.id)) {
                      return;
                    }
                    toggleCategoryCollapsed(category.id);
                  }}
                >
                  <span className="flex min-w-0 items-center gap-2">
                    {collapsed
                      ? <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                    <span className="truncate text-sm font-semibold text-foreground">{category.name}</span>
                    <span className="rounded-md border border-primary/35 bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                      {entries.length}
                    </span>
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {t('vault.dragDrop.dropHint', { defaultValue: 'Einträge hier ablegen' })}
                  </span>
                </button>
                {!collapsed && (
                  <>
                    {tableHeader}
                    {entries.map((entry) => (
                      <VaultItemListTableRow
                        key={entry.item.id}
                        entry={entry}
                        api={api}
                        categoryNameById={categoryNameById}
                      />
                    ))}
                  </>
                )}
              </div>
            );
          })}

          {hasUncategorizedEntries && (
            <div className="space-y-3">
              {(hasCategorizedEntries || hasFavorites || hasRecent) && (
                <div className="px-1 text-sm font-semibold text-foreground">
                  {t('vault.sections.uncategorized', { defaultValue: 'Ohne Kategorie' })}
                </div>
              )}
              <TableWrapper showHeader={hasCategorizedEntries} header={tableHeader}>
                {uncategorizedEntries.map((entry) => (
                  <VaultItemListTableRow
                    key={entry.item.id}
                    entry={entry}
                    api={api}
                    categoryNameById={categoryNameById}
                  />
                ))}
              </TableWrapper>
            </div>
          )}
        </section>
      )}
    </div>
  );
}

interface FavoritesSectionProps {
  readonly entries: readonly RenderableVaultItemEntry[];
  readonly collapsedLimit: number;
  readonly expanded: boolean;
  readonly onToggleExpanded: () => void;
  readonly viewMode: ViewMode;
  readonly api: VaultItemListRowApi;
  readonly scrollerRef: React.RefObject<HTMLDivElement>;
  readonly onPointerDown: React.PointerEventHandler<HTMLDivElement>;
  readonly onPointerMove: React.PointerEventHandler<HTMLDivElement>;
  readonly onPointerEnd: React.PointerEventHandler<HTMLDivElement>;
}

function FavoritesSection({
  entries,
  collapsedLimit,
  expanded,
  onToggleExpanded,
  viewMode,
  api,
  scrollerRef,
  onPointerDown,
  onPointerMove,
  onPointerEnd,
}: FavoritesSectionProps) {
  const { t } = useTranslation();
  const hiddenCount = Math.max(0, entries.length - collapsedLimit);
  const visibleEntries = expanded ? entries : entries.slice(0, collapsedLimit);

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
          <Pin className="h-4 w-4 text-primary" aria-hidden="true" />
          <span>{t('vault.sections.favorites', { defaultValue: 'Favoriten' })}</span>
        </div>
        {hiddenCount > 0 && (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="h-8 rounded-full px-3 text-xs text-primary hover:text-primary"
            onClick={onToggleExpanded}
          >
            {expanded
              ? t('vault.sections.showFewerFavorites', { defaultValue: 'Weniger anzeigen' })
              : t('vault.sections.showMoreFavorites', {
                defaultValue: '+ {{count}} weitere anzeigen',
                count: hiddenCount,
              })}
          </Button>
        )}
      </div>
      {expanded ? (
        <>
          {/* Mobile / tablet: vertikales Grid — versteckt ab lg */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:hidden">
            {visibleEntries.map((entry) => (
              <div key={entry.item.id}>
                <VaultItemListCardRow entry={entry} viewMode={viewMode} api={api} draggable={false} />
              </div>
            ))}
          </div>
          {/* Desktop lg+: horizontaler Wisch-Carousel — versteckt unter lg */}
          <div
            ref={scrollerRef}
            className="scrollbar-hide hidden cursor-grab touch-pan-x select-none gap-4 overflow-x-auto pb-2 pr-4 active:cursor-grabbing lg:flex"
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerEnd}
            onPointerCancel={onPointerEnd}
            onPointerLeave={onPointerEnd}
          >
            {visibleEntries.map((entry) => (
              <div
                key={entry.item.id}
                className="min-w-[240px] max-w-[280px] flex-[0_0_72%] lg:basis-[240px] xl:basis-[220px]"
              >
                <VaultItemListCardRow entry={entry} viewMode={viewMode} api={api} draggable={false} />
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {visibleEntries.map((entry) => (
            <VaultItemListCardRow key={entry.item.id} entry={entry} viewMode={viewMode} api={api} />
          ))}
        </div>
      )}
    </section>
  );
}

interface RecentSectionProps {
  readonly entries: readonly RenderableVaultItemEntry[];
  readonly api: VaultItemListRowApi;
  readonly categoryNameById: ReadonlyMap<string, string>;
  readonly showTopBorder: boolean;
}

function RecentSection({ entries, api, categoryNameById, showTopBorder }: RecentSectionProps) {
  const { t } = useTranslation();

  // Render up to two side-by-side mini tables for "Zuletzt verwendet" so the
  // section uses the available width on wide layouts without resizing rows.
  const columns = [entries.slice(0, 4), entries.slice(4, 8)].filter((column) => column.length > 0);

  return (
    <section className={cn('space-y-3', showTopBorder && 'border-t border-border/35 pt-5')}>
      <div className="flex items-center gap-2 px-1 text-sm font-semibold text-foreground">
        <Clock3 className="h-4 w-4 text-primary" aria-hidden="true" />
        <span>{t('vault.sections.recentlyUsed', { defaultValue: 'Zuletzt verwendet' })}</span>
      </div>
      <div className={cn('grid gap-3', columns.length > 1 && 'xl:grid-cols-2')}>
        {columns.map((column, index) => (
          <div key={`recent-${index}`}>
            <TableWrapper>
              {column.map((entry) => (
                <VaultItemListTableRow
                  key={entry.item.id}
                  entry={entry}
                  api={api}
                  categoryNameById={categoryNameById}
                />
              ))}
            </TableWrapper>
          </div>
        ))}
      </div>
    </section>
  );
}

interface TableWrapperProps {
  readonly children: React.ReactNode;
  readonly showHeader?: boolean;
  readonly header?: React.ReactNode;
}

function TableWrapper({ children, showHeader, header }: TableWrapperProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-[hsl(var(--border)/0.32)] bg-[hsl(var(--el-1)/0.72)] shadow-[0_18px_48px_hsl(0_0%_0%/0.24)] backdrop-blur transition-all duration-200 ease-out">
      {showHeader && header}
      {children}
    </div>
  );
}
