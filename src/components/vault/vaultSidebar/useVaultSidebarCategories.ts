// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Categories Hook
 *
 * Owns the sidebar's "what categories exist + how many items in each?" read
 * path. Mirrors the dual runtime layout of the rest of the app:
 *  - OpLog runtime: derives both categories and counts from the verified
 *    in-memory state.
 *  - Snapshot runtime: loads the snapshot, decrypts categories and items
 *    individually for the count, gracefully treating quarantined / undecodable
 *    items as members of their previously known category so the sidebar
 *    still shows a usable count.
 *
 * Decrypt failures never escape: each failure is cached so the next pass
 * skips it, and only the first occurrence is logged to avoid log floods.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import type { VaultItemData } from '@/services/cryptoService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import { loadVaultSnapshot } from '@/services/offlineVaultService';
import type { VaultSnapshotSource } from '@/contexts/vault/vaultContextTypes';
import { migrateLegacyVaultItemMetadata } from '@/services/legacyVaultMetadataMigrationService';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';

import {
  getVerifiedItemCategoryId,
  mapVerifiedCategoryRecord,
} from './vaultSidebarPlaintextMapper';
import { ENCRYPTED_CATEGORY_PREFIX, type Category } from './vaultSidebarTypes';

interface VaultIntegrityVerificationResult {
  readonly mode?: string;
  readonly quarantinedItems?: { readonly id: string }[];
}

export interface UseVaultSidebarCategoriesInput {
  readonly userId: string | null;
  readonly isDuressMode: boolean;
  readonly useOpLogVerifiedRuntime: boolean;
  readonly opLogLocalVaultState: LocalVaultState | null;
  readonly vaultDataVersion: number;
  readonly lastIntegrityResult: VaultIntegrityVerificationResult | null;
  readonly decryptData: (encrypted: string, aad?: string) => Promise<string>;
  readonly decryptItem: (encrypted: string, itemId: string) => Promise<VaultItemData>;
  readonly verifyIntegrity: (
    snapshot?: OfflineVaultSnapshot,
    options?: { source?: VaultSnapshotSource },
  ) => Promise<VaultIntegrityVerificationResult | null>;
}

export interface UseVaultSidebarCategoriesResult {
  readonly categories: Category[];
  readonly loading: boolean;
  readonly refetch: () => Promise<void>;
}

export function useVaultSidebarCategories({
  userId,
  isDuressMode,
  useOpLogVerifiedRuntime,
  opLogLocalVaultState,
  vaultDataVersion,
  lastIntegrityResult,
  decryptData,
  decryptItem,
  verifyIntegrity,
}: UseVaultSidebarCategoriesInput): UseVaultSidebarCategoriesResult {
  const [categories, setCategories] = useState<Category[]>([]);
  const [loading, setLoading] = useState(true);

  const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
  const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());
  const fetchRequestIdRef = useRef(0);
  const fetchingCategoriesRef = useRef(false);
  const quarantinedItemIdsRef = useRef<Set<string>>(new Set());

  const decryptDataRef = useRef(decryptData);
  const decryptItemRef = useRef(decryptItem);
  const verifyIntegrityRef = useRef(verifyIntegrity);

  useEffect(() => {
    decryptDataRef.current = decryptData;
    decryptItemRef.current = decryptItem;
    verifyIntegrityRef.current = verifyIntegrity;
  }, [decryptData, decryptItem, verifyIntegrity]);

  useEffect(() => {
    failedDecryptPayloadByItemIdRef.current.clear();
    loggedDecryptFailuresRef.current.clear();
  }, [userId, isDuressMode]);

  useEffect(() => {
    quarantinedItemIdsRef.current = new Set(
      (lastIntegrityResult?.quarantinedItems ?? []).map((item) => item.id),
    );
  }, [lastIntegrityResult]);

  const fetchCategories = useCallback(async () => {
    if (!userId || fetchingCategoriesRef.current) return;

    const requestId = fetchRequestIdRef.current + 1;
    fetchRequestIdRef.current = requestId;
    fetchingCategoriesRef.current = true;

    try {
      if (useOpLogVerifiedRuntime) {
        if (!opLogLocalVaultState) {
          if (fetchRequestIdRef.current === requestId) {
            setCategories([]);
          }
          return;
        }

        const counts: Record<string, number> = {};
        for (const record of opLogLocalVaultState.recordsById.values()) {
          const categoryId = getVerifiedItemCategoryId(record);
          if (categoryId) {
            counts[categoryId] = (counts[categoryId] || 0) + 1;
          }
        }

        const resolvedCategories = Array.from(opLogLocalVaultState.recordsById.values())
          .map((record) => mapVerifiedCategoryRecord(record, counts[record.record.recordId] || 0))
          .filter((category): category is Category => category !== null);

        if (fetchRequestIdRef.current === requestId) {
          setCategories(resolvedCategories);
        }
        return;
      }

      const { snapshot, source } = await loadVaultSnapshot(userId);
      // In duress mode the decoy items are in-memory only — do not run a
      // real integrity check (which would always return integrity_unknown
      // because no server manifest exists for the duress key).
      const integrityResult = isDuressMode ? null : await verifyIntegrityRef.current(snapshot, { source });
      if (integrityResult?.mode === 'blocked') {
        if (fetchRequestIdRef.current === requestId) {
          setCategories([]);
        }
        return;
      }
      const counts: Record<string, number> = {};

      await Promise.all(
        snapshot.items.map(async (item) => {
          const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
          if (cachedFailedPayload === item.encrypted_data) {
            if (item.category_id) {
              counts[item.category_id] = (counts[item.category_id] || 0) + 1;
            }
            return;
          }

          // Quarantined items: avoid decrypting beyond the inline single-case
          // limit but still contribute to the prior category's count so the
          // sidebar tally does not visibly drop on a fresh quarantine.
          if (quarantinedItemIdsRef.current.has(item.id)) {
            if (quarantinedItemIdsRef.current.size >= 2) {
              return;
            }
            if (item.category_id) {
              counts[item.category_id] = (counts[item.category_id] || 0) + 1;
            }
            return;
          }

          try {
            const decryptedData = await decryptItemRef.current(item.encrypted_data, item.id);
            failedDecryptPayloadByItemIdRef.current.delete(item.id);

            const migration = await migrateLegacyVaultItemMetadata({
              userId,
              vaultId: snapshot.vaultId,
              item,
              decryptedData,
              canPersistRemote: false,
              encryptItem: async () => {
                throw new Error('legacy metadata writes are disabled');
              },
            });

            const resolvedCategoryId = migration.decryptedData.categoryId ?? migration.item.category_id;

            if (resolvedCategoryId) {
              counts[resolvedCategoryId] = (counts[resolvedCategoryId] || 0) + 1;
            }
          } catch {
            failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
            const logKey = `${item.id}:${item.updated_at}`;
            if (!loggedDecryptFailuresRef.current.has(logKey)) {
              loggedDecryptFailuresRef.current.add(logKey);
              console.debug(
                isDuressMode
                  ? 'Failed to decrypt vault item for category counts (Duress Mode - expected):'
                  : 'Failed to decrypt vault item for category counts (key mismatch or corrupt):',
                item.id,
              );
            }
            if (item.category_id) {
              counts[item.category_id] = (counts[item.category_id] || 0) + 1;
            }
          }
        }),
      );

      const resolvedCategories = await Promise.all(
        snapshot.categories.map((cat) => decryptCategoryRow(cat, counts, isDuressMode, decryptDataRef.current)),
      );

      if (fetchRequestIdRef.current === requestId) {
        setCategories(resolvedCategories);
      }
    } catch (err) {
      console.error('Error fetching categories:', err);
    } finally {
      fetchingCategoriesRef.current = false;
      if (fetchRequestIdRef.current === requestId) {
        setLoading(false);
      }
    }
  }, [
    isDuressMode,
    opLogLocalVaultState,
    useOpLogVerifiedRuntime,
    userId,
  ]);

  useEffect(() => {
    void fetchCategories();
  }, [fetchCategories, vaultDataVersion]);

  return {
    categories,
    loading,
    refetch: fetchCategories,
  };
}

interface SnapshotCategoryRow {
  id: string;
  name: string;
  icon: string | null;
  color: string | null;
}

/**
 * Decrypts the optionally encrypted name/icon/color fields of a snapshot
 * category row. On decrypt failure we log once and fall back to a placeholder
 * so the sidebar stays usable instead of throwing.
 */
async function decryptCategoryRow(
  cat: SnapshotCategoryRow,
  counts: Record<string, number>,
  isDuressMode: boolean,
  decryptData: (encrypted: string, aad?: string) => Promise<string>,
): Promise<Category> {
  let resolvedName = cat.name;
  let resolvedIcon = cat.icon;
  let resolvedColor = cat.color;

  if (cat.name.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    try {
      resolvedName = await decryptData(cat.name.slice(ENCRYPTED_CATEGORY_PREFIX.length));
    } catch {
      console.debug(
        isDuressMode
          ? 'Failed to decrypt category name (Duress Mode - expected):'
          : 'Failed to decrypt category name (key mismatch or corrupt):',
        cat.id,
      );
      resolvedName = 'Beschädigte Kategorie';
    }
  }

  if (cat.icon && cat.icon.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    try {
      resolvedIcon = await decryptData(cat.icon.slice(ENCRYPTED_CATEGORY_PREFIX.length));
    } catch {
      console.debug(
        isDuressMode
          ? 'Failed to decrypt category icon (Duress Mode - expected):'
          : 'Failed to decrypt category icon (key mismatch or corrupt):',
        cat.id,
      );
      resolvedIcon = null;
    }
  }

  if (cat.color && cat.color.startsWith(ENCRYPTED_CATEGORY_PREFIX)) {
    try {
      resolvedColor = await decryptData(cat.color.slice(ENCRYPTED_CATEGORY_PREFIX.length));
    } catch {
      console.debug(
        isDuressMode
          ? 'Failed to decrypt category color (Duress Mode - expected):'
          : 'Failed to decrypt category color (key mismatch or corrupt):',
        cat.id,
      );
      resolvedColor = '#3b82f6';
    }
  }

  return {
    id: cat.id,
    name: resolvedName,
    icon: resolvedIcon,
    color: resolvedColor,
    count: counts[cat.id] || 0,
  };
}
