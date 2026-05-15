// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Mutations Hook
 *
 * Concentrates the three write paths the list triggers locally:
 *  - moving an item to a different category (drag/drop)
 *  - toggling an item's favorite flag (star button / preview panel)
 *  - deleting an item (preview delete dialog)
 *
 * All three follow the same pattern: optimistic UI update, dispatch the
 * write through the OpLog, surface a toast on failure and revert the
 * optimistic update so the displayed state matches the verified vault.
 *
 * A small client-side cooldown on favorite writes prevents an excited
 * double-tap from racing two concurrent writes against the OpLog. Keeping
 * this cooldown here (instead of inside a button) ensures every entry point
 * that calls `toggleFavorite` shares the same back-pressure.
 */

import { useCallback, useRef } from 'react';
import type { Dispatch, SetStateAction } from 'react';

import type { LocalVerifiedRecord, LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';
import type { ItemPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';

import {
  getItemCategoryId,
  isItemFavorite,
  type VaultItem,
} from './vaultItemModel';
import {
  itemPlaintextFromVaultItem,
  parseVerifiedPlaintextObject,
} from './vaultItemPlaintextMapper';

const FAVORITE_ACTION_COOLDOWN_MS = 3_000;

export interface OpLogWriteResult {
  readonly error: { readonly message: string } | null;
}

export interface UseVaultItemMutationsInput {
  readonly items: readonly VaultItem[];
  readonly setItems: Dispatch<SetStateAction<VaultItem[]>>;
  readonly opLogLocalVaultState: LocalVaultState | null;
  readonly opLogUpdateItem: (itemId: string, plaintext: ItemPlaintext) => Promise<OpLogWriteResult>;
  readonly opLogDeleteItem: (itemId: string) => Promise<OpLogWriteResult>;
  readonly onMarkRecentlyUsed: (itemId: string) => void;
  readonly onError: (message: string) => void;
  readonly onFavoriteCooldown: (remainingSeconds: number) => void;
}

export interface UseVaultItemMutationsResult {
  readonly moveItemToCategory: (itemId: string, nextCategoryId: string | null) => Promise<void>;
  readonly toggleItemFavorite: (item: VaultItem) => Promise<void>;
  readonly deleteItem: (itemId: string) => Promise<{ ok: boolean }>;
}

function sourcePlaintextFor(
  opLogLocalVaultState: LocalVaultState | null,
  itemId: string,
): Record<string, unknown> | null {
  return parseVerifiedPlaintextObject(
    opLogLocalVaultState?.recordsById.get(itemId) as LocalVerifiedRecord | undefined,
  );
}

export function useVaultItemMutations({
  items,
  setItems,
  opLogLocalVaultState,
  opLogUpdateItem,
  opLogDeleteItem,
  onMarkRecentlyUsed,
  onError,
  onFavoriteCooldown,
}: UseVaultItemMutationsInput): UseVaultItemMutationsResult {
  const nextFavoriteActionAtRef = useRef(0);

  const moveItemToCategory = useCallback(async (itemId: string, nextCategoryId: string | null) => {
    const item = items.find((candidate) => candidate.id === itemId);
    if (!item) {
      return;
    }

    const previousCategoryId = getItemCategoryId(item);
    if (previousCategoryId === nextCategoryId) {
      return;
    }

    const plaintext = itemPlaintextFromVaultItem(
      item,
      { categoryRecordId: nextCategoryId },
      sourcePlaintextFor(opLogLocalVaultState, itemId),
    );
    if (!plaintext) {
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        category_id: nextCategoryId,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, categoryId: nextCategoryId }
          : currentItem.decryptedData,
      };
    }));
    onMarkRecentlyUsed(item.id);

    const result = await opLogUpdateItem(item.id, plaintext);
    if (!result.error) {
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        category_id: previousCategoryId,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, categoryId: previousCategoryId }
          : currentItem.decryptedData,
      };
    }));
    onError(result.error.message);
  }, [items, onError, onMarkRecentlyUsed, opLogLocalVaultState, opLogUpdateItem, setItems]);

  const toggleItemFavorite = useCallback(async (item: VaultItem) => {
    const now = Date.now();
    const remainingMs = nextFavoriteActionAtRef.current - now;
    if (remainingMs > 0) {
      onFavoriteCooldown(Math.max(1, Math.ceil(remainingMs / 1000)));
      return;
    }

    nextFavoriteActionAtRef.current = now + FAVORITE_ACTION_COOLDOWN_MS;
    const nextFavorite = !isItemFavorite(item);
    const plaintext = itemPlaintextFromVaultItem(
      item,
      { isFavorite: nextFavorite },
      sourcePlaintextFor(opLogLocalVaultState, item.id),
    );
    if (!plaintext) {
      nextFavoriteActionAtRef.current = 0;
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        is_favorite: nextFavorite,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, isFavorite: nextFavorite }
          : currentItem.decryptedData,
      };
    }));
    onMarkRecentlyUsed(item.id);

    const result = await opLogUpdateItem(item.id, plaintext);
    if (!result.error) {
      return;
    }

    nextFavoriteActionAtRef.current = 0;
    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        is_favorite: !nextFavorite,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, isFavorite: !nextFavorite }
          : currentItem.decryptedData,
      };
    }));
    onError(result.error.message);
  }, [onError, onFavoriteCooldown, onMarkRecentlyUsed, opLogLocalVaultState, opLogUpdateItem, setItems]);

  const deleteItem = useCallback(async (itemId: string) => {
    const result = await opLogDeleteItem(itemId);
    if (result.error) {
      onError(result.error.message);
      return { ok: false };
    }

    setItems((current) => current.filter((item) => item.id !== itemId));
    return { ok: true };
  }, [onError, opLogDeleteItem, setItems]);

  return {
    moveItemToCategory,
    toggleItemFavorite,
    deleteItem,
  };
}
