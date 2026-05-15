// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Pointer Drag Hook
 *
 * Pointer-Events-based drag-and-drop for vault list rows. Provides a small
 * state machine (idle -> pending -> active -> dropped/cancelled) plus the
 * handlers the grip handle button needs to wire up.
 *
 * Native HTML5 drag still drives the desktop mouse path via the row itself;
 * this hook covers touch/pen and adds the "drag to category" affordance with a
 * touch-friendly activation delay and movement threshold so casual taps do
 * not start a drag.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';

import { getItemTitle, type VaultItem } from './vaultItemModel';

const TOUCH_DRAG_ACTIVATION_MS = 260;
const TOUCH_DRAG_MOVE_THRESHOLD_PX = 8;
const DRAG_SCROLL_EDGE_PX = 96;
const DRAG_SCROLL_STEP_PX = 28;

export interface PointerDragState {
  readonly itemId: string;
  readonly title: string;
  readonly pointerId: number;
  readonly pointerType: string;
  readonly active: boolean;
  readonly originX: number;
  readonly originY: number;
  readonly x: number;
  readonly y: number;
  readonly dropCategoryId: string | null;
}

export interface UseVaultItemPointerDragInput {
  onMoveItemToCategory: (itemId: string, categoryId: string) => void;
  onDropTargetChange: (categoryId: string | null) => void;
}

export interface UseVaultItemPointerDragResult {
  pointerDrag: PointerDragState | null;
  startPointerDrag: (item: VaultItem, event: ReactPointerEvent<HTMLElement>) => void;
  handlePointerDragMove: (event: ReactPointerEvent<HTMLElement>) => void;
  completePointerDrag: (event: ReactPointerEvent<HTMLElement>) => void;
  cancelPointerDrag: (event?: ReactPointerEvent<HTMLElement>) => void;
}

/**
 * Auto-scrolls the viewport when the pointer/native drag approaches the edge.
 *
 * Exported so the native HTML5 drag path can call it from its global
 * `dragover` listener — keeps a single source of truth for the edge scroll
 * behaviour.
 */
export function scrollViewportForDrag(clientY: number): void {
  if (typeof window === 'undefined' || !Number.isFinite(clientY)) {
    return;
  }

  const viewportHeight = window.innerHeight || 0;
  if (viewportHeight <= 0) {
    return;
  }

  if (clientY < DRAG_SCROLL_EDGE_PX) {
    window.scrollBy({ top: -DRAG_SCROLL_STEP_PX, behavior: 'auto' });
  } else if (clientY > viewportHeight - DRAG_SCROLL_EDGE_PX) {
    window.scrollBy({ top: DRAG_SCROLL_STEP_PX, behavior: 'auto' });
  }
}

function resolveCategoryDropIdAtPoint(x: number, y: number): string | null {
  if (typeof document === 'undefined') {
    return null;
  }

  const element = document.elementFromPoint(x, y);
  const dropTarget = element?.closest<HTMLElement>('[data-vault-category-drop-id]');
  return dropTarget?.dataset.vaultCategoryDropId ?? null;
}

export function useVaultItemPointerDrag({
  onMoveItemToCategory,
  onDropTargetChange,
}: UseVaultItemPointerDragInput): UseVaultItemPointerDragResult {
  const [pointerDrag, setPointerDrag] = useState<PointerDragState | null>(null);
  const pointerDragRef = useRef<PointerDragState | null>(null);
  const pointerDragTimerRef = useRef<number | null>(null);

  const setPointerDragState = useCallback((nextState: PointerDragState | null) => {
    pointerDragRef.current = nextState;
    setPointerDrag(nextState);
  }, []);

  const clearPointerDragTimer = useCallback(() => {
    if (pointerDragTimerRef.current !== null) {
      window.clearTimeout(pointerDragTimerRef.current);
      pointerDragTimerRef.current = null;
    }
  }, []);

  const releasePointerCapture = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    try {
      event.currentTarget.releasePointerCapture(event.pointerId);
    } catch {
      // Some test and WebView runtimes expose Pointer Events without capture support.
    }
  }, []);

  const cancelPointerDrag = useCallback((event?: ReactPointerEvent<HTMLElement>) => {
    clearPointerDragTimer();
    if (event) {
      releasePointerCapture(event);
    }
    onDropTargetChange(null);
    setPointerDragState(null);
  }, [clearPointerDragTimer, onDropTargetChange, releasePointerCapture, setPointerDragState]);

  const startPointerDrag = useCallback((item: VaultItem, event: ReactPointerEvent<HTMLElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    clearPointerDragTimer();
    const originX = Number.isFinite(event.clientX) ? event.clientX : 0;
    const originY = Number.isFinite(event.clientY) ? event.clientY : 0;
    const activeImmediately = event.pointerType !== 'touch';
    const initialDropCategoryId = activeImmediately
      ? resolveCategoryDropIdAtPoint(originX, originY)
      : null;

    const initialState: PointerDragState = {
      itemId: item.id,
      title: getItemTitle(item),
      pointerId: event.pointerId,
      pointerType: event.pointerType,
      active: activeImmediately,
      originX,
      originY,
      x: originX,
      y: originY,
      dropCategoryId: initialDropCategoryId,
    };
    setPointerDragState(initialState);
    if (activeImmediately) {
      onDropTargetChange(initialDropCategoryId);
    }

    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // Pointer capture is best-effort; native browser drag remains available for mouse users.
    }

    if (activeImmediately) {
      return;
    }

    // Touch path: defer activation so a casual tap (without crossing the move
    // threshold below) is still a click and not an accidental drag.
    pointerDragTimerRef.current = window.setTimeout(() => {
      const current = pointerDragRef.current;
      if (!current || current.pointerId !== event.pointerId) {
        return;
      }

      const dropCategoryId = resolveCategoryDropIdAtPoint(current.x, current.y);
      setPointerDragState({
        ...current,
        active: true,
        dropCategoryId,
      });
      onDropTargetChange(dropCategoryId);
    }, TOUCH_DRAG_ACTIVATION_MS);
  }, [clearPointerDragTimer, onDropTargetChange, setPointerDragState]);

  const handlePointerDragMove = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    const current = pointerDragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }

    const x = Number.isFinite(event.clientX) ? event.clientX : current.x;
    const y = Number.isFinite(event.clientY) ? event.clientY : current.y;
    const deltaX = x - current.originX;
    const deltaY = y - current.originY;
    const movedDistance = Math.hypot(deltaX, deltaY);
    if (!current.active && movedDistance > TOUCH_DRAG_MOVE_THRESHOLD_PX) {
      cancelPointerDrag(event);
      return;
    }

    const dropCategoryId = current.active
      ? resolveCategoryDropIdAtPoint(x, y)
      : current.dropCategoryId;
    const nextState: PointerDragState = {
      ...current,
      x,
      y,
      dropCategoryId,
    };
    setPointerDragState(nextState);

    if (current.active) {
      event.preventDefault();
      event.stopPropagation();
      scrollViewportForDrag(y);
      onDropTargetChange(dropCategoryId);
    }
  }, [cancelPointerDrag, onDropTargetChange, setPointerDragState]);

  const completePointerDrag = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    const current = pointerDragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }

    clearPointerDragTimer();
    releasePointerCapture(event);
    setPointerDragState(null);
    onDropTargetChange(null);

    if (!current.active) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    const x = Number.isFinite(event.clientX) ? event.clientX : current.x;
    const y = Number.isFinite(event.clientY) ? event.clientY : current.y;
    const dropCategoryId = current.dropCategoryId ?? resolveCategoryDropIdAtPoint(x, y);
    if (dropCategoryId) {
      onMoveItemToCategory(current.itemId, dropCategoryId);
    }
  }, [
    clearPointerDragTimer,
    onDropTargetChange,
    onMoveItemToCategory,
    releasePointerCapture,
    setPointerDragState,
  ]);

  useEffect(() => () => {
    clearPointerDragTimer();
  }, [clearPointerDragTimer]);

  return {
    pointerDrag,
    startPointerDrag,
    handlePointerDragMove,
    completePointerDrag,
    cancelPointerDrag,
  };
}
