// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Row API
 *
 * A small bundle of state + callbacks that the list passes to every row
 * (card or table). Bundling them keeps the row component signatures stable
 * and prevents the main list from threading 10+ props through every
 * intermediate JSX call.
 */

import type { PointerEvent as ReactPointerEvent } from 'react';

import type { VaultItem } from './vaultItemModel';

export interface VaultItemListRowApi {
  readonly highlightedItemId: string | null;
  readonly canCopySecrets: (itemId: string) => boolean;
  readonly registerElement: (itemId: string, element: HTMLDivElement | null) => void;
  readonly onNativeDragStart: (itemId: string) => void;
  readonly onNativeDragEnd: () => void;
  readonly onMarkRecentlyUsed: (itemId: string) => void;
  readonly onOpenPreview: (item: VaultItem) => void;
  readonly onEditFromPreview: (itemId: string) => void;
  readonly onToggleFavorite: (item: VaultItem) => void;
  readonly onCopyUsername: (item: VaultItem, value: string | null | undefined) => void;
  readonly onCopyPassword: (item: VaultItem, value: string | null | undefined) => void;
  readonly pointerDrag: {
    readonly start: (item: VaultItem, event: ReactPointerEvent<HTMLElement>) => void;
    readonly move: (event: ReactPointerEvent<HTMLElement>) => void;
    readonly complete: (event: ReactPointerEvent<HTMLElement>) => void;
    readonly cancel: (event?: ReactPointerEvent<HTMLElement>) => void;
  };
}

export const VAULT_ITEM_DRAG_MIME = 'application/x-singra-vault-item-id';
