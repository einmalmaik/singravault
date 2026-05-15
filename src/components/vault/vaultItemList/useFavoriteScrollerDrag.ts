// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Favorite Carousel Drag Hook
 *
 * Adds "grab and pan" horizontal scrolling to the favorites carousel without
 * interfering with clicks on the embedded card buttons.
 *
 * A small movement threshold prevents accidental drags so quick taps on the
 * carousel cards still register as clicks.
 */

import { useCallback, useRef } from 'react';
import type { PointerEvent as ReactPointerEvent, RefObject } from 'react';

const DRAG_ACTIVATION_THRESHOLD_PX = 4;

interface FavoriteScrollDragState {
  pointerId: number;
  startX: number;
  scrollLeft: number;
  dragging: boolean;
}

export interface UseFavoriteScrollerDragResult {
  scrollerRef: RefObject<HTMLDivElement>;
  onPointerDown: (event: ReactPointerEvent<HTMLDivElement>) => void;
  onPointerMove: (event: ReactPointerEvent<HTMLDivElement>) => void;
  onPointerEnd: (event: ReactPointerEvent<HTMLDivElement>) => void;
}

export function useFavoriteScrollerDrag(): UseFavoriteScrollerDragResult {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const dragStateRef = useRef<FavoriteScrollDragState | null>(null);

  const onPointerDown = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) {
      return;
    }

    const target = event.target as HTMLElement | null;
    if (target?.closest('button,a,input,textarea,select,[role="button"]')) {
      return;
    }

    const scroller = scrollerRef.current;
    if (!scroller) {
      return;
    }

    dragStateRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      scrollLeft: scroller.scrollLeft,
      dragging: false,
    };
    try {
      scroller.setPointerCapture(event.pointerId);
    } catch {
      dragStateRef.current = null;
    }
  }, []);

  const onPointerMove = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const current = dragStateRef.current;
    const scroller = scrollerRef.current;
    if (!current || !scroller || current.pointerId !== event.pointerId) {
      return;
    }

    const deltaX = event.clientX - current.startX;
    if (Math.abs(deltaX) > DRAG_ACTIVATION_THRESHOLD_PX) {
      current.dragging = true;
    }
    if (!current.dragging) {
      return;
    }

    event.preventDefault();
    scroller.scrollLeft = current.scrollLeft - deltaX;
  }, []);

  const onPointerEnd = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const scroller = scrollerRef.current;
    if (scroller) {
      try {
        scroller.releasePointerCapture(event.pointerId);
      } catch {
        dragStateRef.current = null;
      }
    }
    dragStateRef.current = null;
  }, []);

  return {
    scrollerRef,
    onPointerDown,
    onPointerMove,
    onPointerEnd,
  };
}
