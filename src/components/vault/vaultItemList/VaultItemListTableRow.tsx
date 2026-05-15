// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Table Row
 *
 * Wide-screen layout for a vault item shown inside the dashboard tables
 * (recent, per-category, uncategorized). Implements the inline
 * copy/edit/favorite controls and integrates with the same pointer-drag and
 * native HTML5 drag affordances as the card row.
 *
 * Copy controls are gated by `canCopySecrets` so locked/unverified vault
 * states never expose copy buttons even if the row is otherwise rendered.
 */

import { useTranslation } from 'react-i18next';
import { Copy, Edit, KeyRound, Star } from 'lucide-react';

import { Button } from '@/components/ui/button';
import { VaultIcon } from '@/components/icons/VaultIcon';
import { cn } from '@/lib/utils';

import {
  formatRelativeUpdatedAt,
  getItemCategoryId,
  getItemTitle,
  getItemUsername,
  getItemWebsiteUrl,
  isItemFavorite,
  type RenderableVaultItemEntry,
} from './vaultItemModel';
import { VaultItemListPointerDragHandle } from './VaultItemListPointerDragHandle';
import { VAULT_ITEM_DRAG_MIME, type VaultItemListRowApi } from './vaultItemListRowApi';

interface VaultItemListTableRowProps {
  readonly entry: RenderableVaultItemEntry;
  readonly api: VaultItemListRowApi;
  readonly categoryNameById: ReadonlyMap<string, string>;
  readonly showCategory?: boolean;
}

export function VaultItemListTableRow({
  entry,
  api,
  categoryNameById,
  showCategory,
}: VaultItemListTableRowProps) {
  const { t } = useTranslation();
  const { item } = entry;
  const title = getItemTitle(item);
  const websiteUrl = getItemWebsiteUrl(item);
  const username = getItemUsername(item);
  const password = item.decryptedData?.password ?? null;
  const favorite = isItemFavorite(item);
  const resolvedCategoryId = getItemCategoryId(item);
  const canCopy = api.canCopySecrets(item.id);

  return (
    <div
      ref={(element) => api.registerElement(item.id, element)}
      data-vault-item-id={item.id}
      draggable
      onDragStart={(event) => {
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData(VAULT_ITEM_DRAG_MIME, item.id);
        event.dataTransfer.setData('text/plain', item.id);
        api.onNativeDragStart(item.id);
      }}
      onDragEnd={api.onNativeDragEnd}
      className={cn(
        'group grid min-h-14 cursor-pointer grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-[hsl(var(--border)/0.22)] px-3 py-2.5 transition-all duration-500 ease-out hover:bg-white/[0.035] md:grid-cols-[minmax(210px,1.3fr)_minmax(120px,0.9fr)_minmax(110px,0.8fr)_minmax(110px,0.8fr)_132px]',
        api.highlightedItemId === item.id
          && 'relative z-10 bg-[hsl(var(--primary)/0.08)] ring-2 ring-primary/70 shadow-[0_0_0_1px_hsl(var(--primary)/0.24),0_0_32px_hsl(var(--primary)/0.28)]',
      )}
      onClick={() => api.onOpenPreview(item)}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <VaultItemListPointerDragHandle
          item={item}
          className="border-transparent bg-transparent shadow-none"
          onPointerDown={api.pointerDrag.start}
          onPointerMove={api.pointerDrag.move}
          onPointerUp={api.pointerDrag.complete}
          onPointerCancel={api.pointerDrag.cancel}
        />
        <VaultIcon title={title} websiteUrl={websiteUrl} className="h-7 w-7 shrink-0" />
        <div className="min-w-0">
          <button
            type="button"
            className="block max-w-full truncate text-left text-sm font-medium text-foreground hover:text-primary"
            onClick={(event) => {
              event.stopPropagation();
              api.onOpenPreview(item);
            }}
          >
            {title}
          </button>
          {showCategory && resolvedCategoryId && (
            <p className="mt-0.5 truncate text-[11px] text-muted-foreground md:hidden">
              {categoryNameById.get(resolvedCategoryId) ?? t('categories.category', { defaultValue: 'Kategorie' })}
            </p>
          )}
        </div>
      </div>

      <span className="hidden min-w-0 truncate text-sm text-muted-foreground md:block">
        {username || '—'}
      </span>
      <span className="hidden font-mono text-sm tracking-[0.18em] text-muted-foreground md:block">
        {password ? '••••••••••' : '—'}
      </span>
      <span className="hidden min-w-0 text-sm text-muted-foreground md:block">
        {showCategory && resolvedCategoryId
          ? categoryNameById.get(resolvedCategoryId) ?? '—'
          : formatRelativeUpdatedAt(item.updated_at)}
      </span>

      <div className="flex items-center justify-end gap-1">
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className={cn(
            'h-10 w-10 text-muted-foreground hover:text-amber-300 sm:h-8 sm:w-8',
            favorite && 'text-amber-400',
          )}
          aria-label={favorite
            ? t('vault.actions.removeFavorite', { defaultValue: 'Favorit entfernen' })
            : t('vault.actions.addFavorite', { defaultValue: 'Als Favorit markieren' })}
          onClick={(event) => {
            event.stopPropagation();
            api.onToggleFavorite(item);
          }}
        >
          <Star className={cn('h-4 w-4', favorite && 'fill-current')} />
        </Button>
        {username && canCopy && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
            aria-label={t('vault.actions.copyUsername')}
            onClick={(event) => {
              event.stopPropagation();
              api.onCopyUsername(item, username);
            }}
          >
            <Copy className="h-4 w-4" />
          </Button>
        )}
        {password && canCopy && (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
            aria-label={t('vault.actions.copyPassword')}
            onClick={(event) => {
              event.stopPropagation();
              api.onCopyPassword(item, password);
            }}
          >
            <KeyRound className="h-4 w-4" />
          </Button>
        )}
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
          aria-label={t('common.edit')}
          onClick={(event) => {
            event.stopPropagation();
            api.onEditFromPreview(item.id);
          }}
        >
          <Edit className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}
