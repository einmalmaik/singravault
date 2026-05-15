// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Focus Highlight Hook
 *
 * Briefly highlights a row scrolled-to from outside the list (e.g. the vault
 * health report linking to a specific item). Owns:
 *  - the highlighted item id and its visible-pulse timer
 *  - the per-row DOM element registry used for `scrollIntoView`
 *  - de-duplication so the highlight does not retrigger on every parent
 *    rerender while the same `focusItemId` is set
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import type { RenderableVaultItemEntry } from './vaultItemModel';

const FOCUS_HIGHLIGHT_MS = 10_000;

export interface UseVaultItemFocusHighlightInput {
  readonly focusItemId: string | null;
  readonly visibleItemEntries: readonly RenderableVaultItemEntry[];
  readonly onFocusVisible: (itemId: string) => void;
}

export interface UseVaultItemFocusHighlightResult {
  readonly highlightedItemId: string | null;
  readonly registerElement: (itemId: string, element: HTMLDivElement | null) => void;
}

export function useVaultItemFocusHighlight({
  focusItemId,
  visibleItemEntries,
  onFocusVisible,
}: UseVaultItemFocusHighlightInput): UseVaultItemFocusHighlightResult {
  const [highlightedItemId, setHighlightedItemId] = useState<string | null>(null);
  const itemElementRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const focusHighlightTimerRef = useRef<number | null>(null);
  const lastHandledFocusItemIdRef = useRef<string | null>(null);

  useEffect(() => () => {
    if (focusHighlightTimerRef.current !== null) {
      window.clearTimeout(focusHighlightTimerRef.current);
    }
  }, []);

  useEffect(() => {
    if (!focusItemId) {
      lastHandledFocusItemIdRef.current = null;
      return;
    }

    if (lastHandledFocusItemIdRef.current === focusItemId) {
      return;
    }

    const focusedEntry = visibleItemEntries.find((entry) => entry.item.id === focusItemId);
    if (!focusedEntry) {
      return;
    }

    lastHandledFocusItemIdRef.current = focusItemId;
    onFocusVisible(focusItemId);
    setHighlightedItemId(focusItemId);

    // Defer scroll into the next paint frame so the row has been rendered.
    window.requestAnimationFrame(() => {
      itemElementRefs.current.get(focusItemId)?.scrollIntoView({
        block: 'center',
        behavior: 'smooth',
      });
    });

    if (focusHighlightTimerRef.current !== null) {
      window.clearTimeout(focusHighlightTimerRef.current);
    }
    focusHighlightTimerRef.current = window.setTimeout(() => {
      setHighlightedItemId((current) => (current === focusItemId ? null : current));
      focusHighlightTimerRef.current = null;
    }, FOCUS_HIGHLIGHT_MS);
  }, [focusItemId, onFocusVisible, visibleItemEntries]);

  const registerElement = useCallback((itemId: string, element: HTMLDivElement | null) => {
    if (element) {
      itemElementRefs.current.set(itemId, element);
      return;
    }
    itemElementRefs.current.delete(itemId);
  }, []);

  return {
    highlightedItemId,
    registerElement,
  };
}
