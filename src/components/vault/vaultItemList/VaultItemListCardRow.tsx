// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Card Row
 *
 * Wraps `VaultItemCard` with the drag affordances the list relies on:
 * - a focusable pointer-drag grip handle for touch / keyboard users
 * - native HTML5 drag for mouse users (which the parent uses to drop on
 *   category headers in the dashboard)
 * - a focus highlight ring driven by the parent's `highlightedItemId`
 *
 * `draggable={false}` disables native drag when the row sits in the favorite
 * carousel, where horizontal panning would otherwise compete with the drag.
 */

import type { ViewMode } from '@/pages/VaultPage';
import { cn } from '@/lib/utils';

import { VaultItemCard } from '../VaultItemCard';
import { VaultItemListPointerDragHandle } from './VaultItemListPointerDragHandle';
import type { RenderableVaultItemEntry } from './vaultItemModel';
import { VAULT_ITEM_DRAG_MIME, type VaultItemListRowApi } from './vaultItemListRowApi';

interface VaultItemListCardRowProps {
  readonly entry: RenderableVaultItemEntry;
  readonly viewMode: ViewMode;
  readonly api: VaultItemListRowApi;
  readonly draggable?: boolean;
}

export function VaultItemListCardRow({
  entry,
  viewMode,
  api,
  draggable = true,
}: VaultItemListCardRowProps) {
  const { item } = entry;
  return (
    <div
      ref={(element) => api.registerElement(item.id, element)}
      data-vault-item-id={item.id}
      className={cn(
        'group/drag relative rounded-2xl transition-[box-shadow,transform] duration-500',
        api.highlightedItemId === item.id
          && 'ring-2 ring-primary/70 shadow-[0_0_0_1px_hsl(var(--primary)/0.24),0_0_32px_hsl(var(--primary)/0.28)]',
      )}
      draggable={draggable}
      onDragStart={(event) => {
        if (!draggable) {
          event.preventDefault();
          return;
        }
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData(VAULT_ITEM_DRAG_MIME, item.id);
        event.dataTransfer.setData('text/plain', item.id);
        api.onNativeDragStart(item.id);
      }}
      onDragEnd={api.onNativeDragEnd}
    >
      <VaultItemListPointerDragHandle
        item={item}
        className="absolute -left-2 top-2 z-20 opacity-0 sm:group-hover/drag:opacity-100 sm:focus-visible:opacity-100"
        onPointerDown={api.pointerDrag.start}
        onPointerMove={api.pointerDrag.move}
        onPointerUp={api.pointerDrag.complete}
        onPointerCancel={api.pointerDrag.cancel}
      />
      <VaultItemCard
        item={item}
        viewMode={viewMode}
        onEdit={() => api.onOpenPreview(item)}
        onSecretCopied={api.onMarkRecentlyUsed}
        canCopySecrets={api.canCopySecrets(item.id)}
      />
    </div>
  );
}
