// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Ignored Quarantine Hook
 *
 * Tracks which quarantined entries the user explicitly dismissed for the
 * current account. The state is persisted per user under a dedicated
 * `localStorage` key so the UI can hide the noisy banner across reloads while
 * the underlying quarantine state in the vault remains untouched.
 *
 * Storage key contains only public quarantine ids + token (reason + updatedAt),
 * never plaintext vault data.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';

import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';

import { getQuarantineIgnoreToken } from './vaultItemModel';

const STORAGE_KEY_PREFIX = 'singra:vault-quarantine-ignored-items:';

export interface UseVaultIgnoredQuarantineInput {
  readonly userId: string | null;
  readonly quarantinedItems: readonly QuarantinedVaultItem[];
}

export interface UseVaultIgnoredQuarantineResult {
  readonly ignoredQuarantineById: Record<string, string>;
  readonly activeIgnoredQuarantinedItems: QuarantinedVaultItem[];
  readonly activeIgnoredQuarantineIds: Set<string>;
  readonly showIgnoredQuarantine: boolean;
  readonly setShowIgnoredQuarantine: (next: boolean) => void;
  readonly ignoreItem: (item: QuarantinedVaultItem) => void;
  readonly ignoreItems: (items: readonly QuarantinedVaultItem[]) => void;
}

function getStorageKey(userId: string | null): string | null {
  return userId ? `${STORAGE_KEY_PREFIX}${userId}` : null;
}

export function useVaultIgnoredQuarantine({
  userId,
  quarantinedItems,
}: UseVaultIgnoredQuarantineInput): UseVaultIgnoredQuarantineResult {
  const storageKey = getStorageKey(userId);
  const [ignoredQuarantineById, setIgnoredQuarantineById] = useState<Record<string, string>>({});
  const [showIgnoredQuarantine, setShowIgnoredQuarantine] = useState(false);

  // Reload the per-user ignored set whenever the active account changes.
  // Clears `showIgnoredQuarantine` so the previous account's "show ignored"
  // toggle does not leak across user switches.
  useEffect(() => {
    setShowIgnoredQuarantine(false);

    if (!storageKey || typeof window === 'undefined') {
      setIgnoredQuarantineById({});
      return;
    }

    try {
      const parsed = JSON.parse(window.localStorage.getItem(storageKey) || '{}');
      setIgnoredQuarantineById(
        parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? parsed as Record<string, string>
          : {},
      );
    } catch {
      setIgnoredQuarantineById({});
    }
  }, [storageKey]);

  const persistIgnored = useCallback((nextIgnoredById: Record<string, string>) => {
    if (!storageKey || typeof window === 'undefined') {
      return;
    }

    window.localStorage.setItem(storageKey, JSON.stringify(nextIgnoredById));
    setIgnoredQuarantineById(nextIgnoredById);
  }, [storageKey]);

  const ignoreItem = useCallback((item: QuarantinedVaultItem) => {
    persistIgnored({
      ...ignoredQuarantineById,
      [item.id]: getQuarantineIgnoreToken(item),
    });
  }, [ignoredQuarantineById, persistIgnored]);

  const ignoreItems = useCallback((items: readonly QuarantinedVaultItem[]) => {
    persistIgnored({
      ...ignoredQuarantineById,
      ...Object.fromEntries(items.map((item) => [item.id, getQuarantineIgnoreToken(item)])),
    });
  }, [ignoredQuarantineById, persistIgnored]);

  // An ignored entry stays ignored only as long as its quarantine state token
  // (reason + updatedAt) matches the stored one. A fresh incident automatically
  // surfaces again instead of staying silent under the previous acknowledgement.
  const activeIgnoredQuarantinedItems = useMemo(
    () => quarantinedItems.filter(
      (item) => ignoredQuarantineById[item.id] === getQuarantineIgnoreToken(item),
    ),
    [ignoredQuarantineById, quarantinedItems],
  );

  const activeIgnoredQuarantineIds = useMemo(
    () => new Set(activeIgnoredQuarantinedItems.map((item) => item.id)),
    [activeIgnoredQuarantinedItems],
  );

  return {
    ignoredQuarantineById,
    activeIgnoredQuarantinedItems,
    activeIgnoredQuarantineIds,
    showIgnoredQuarantine,
    setShowIgnoredQuarantine,
    ignoreItem,
    ignoreItems,
  };
}
