// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Pointer Drag Grip Handle
 *
 * The dedicated touch-friendly grip handle used by card and table rows to
 * initiate a pointer-based drag. Native HTML5 drag still works through the
 * row itself; the grip handle is the explicit affordance for touch and
 * keyboard users who can focus it.
 */

import type { PointerEvent as ReactPointerEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { GripVertical } from 'lucide-react';

import { cn } from '@/lib/utils';

import type { VaultItem } from './vaultItemModel';

interface VaultItemListPointerDragHandleProps {
  readonly item: VaultItem;
  readonly className?: string;
  readonly onPointerDown: (item: VaultItem, event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerMove: (event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerUp: (event: ReactPointerEvent<HTMLElement>) => void;
  readonly onPointerCancel: (event?: ReactPointerEvent<HTMLElement>) => void;
}

export function VaultItemListPointerDragHandle({
  item,
  className,
  onPointerDown,
  onPointerMove,
  onPointerUp,
  onPointerCancel,
}: VaultItemListPointerDragHandleProps) {
  const { t } = useTranslation();
  return (
    <button
      type="button"
      className={cn(
        'inline-flex h-10 w-10 shrink-0 touch-none items-center justify-center rounded-md border border-border/35 bg-background/80 text-muted-foreground shadow-sm backdrop-blur transition-colors hover:border-primary/55 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45 sm:h-8 sm:w-8',
        className,
      )}
      aria-label={t('vault.dragDrop.dragHandle', { defaultValue: 'Eintrag verschieben' })}
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => onPointerDown(item, event)}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerCancel}
    >
      <GripVertical className="h-4 w-4" aria-hidden="true" />
    </button>
  );
}
