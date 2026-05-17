// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Data Hook
 *
 * Owns the read path of the vault list: snapshot load, integrity gate, batched
 * decryption, legacy migration, OpLog projection, cloud revalidation and the
 * background-sync indicator state.
 *
 * Centralising this in one hook keeps `VaultItemList.tsx` focused on rendering
 * and interaction. Any change to the "what shows up in the list?" pipeline
 * (cache vs. remote, healthy vs. quarantine, legacy v1 envelope migration)
 * must stay in this file so the security gate stays in one place.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import {
  isAppOnline,
  loadVaultSnapshot,
} from '@/services/offlineVaultService';
import {
  LegacyVaultMetadataMigrationPersistenceError,
  migrateLegacyVaultItemEncryptionAndMetadata,
  migrateLegacyVaultItemMetadata,
} from '@/services/legacyVaultMetadataMigrationService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { isVaultItemEnvelopeV2 } from '@/services/vaultIntegrityV2/itemEnvelopeCrypto';
import type { VaultItemData } from '@/services/cryptoService';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';

import {
  canDecryptFromIntegrityResult,
  mapInBatches,
  type VaultItem,
  type VaultItemListIntegrityGate,
} from './vaultItemModel';
import { mapOpLogRecordToVaultItem } from './vaultItemPlaintextMapper';

const DECRYPT_BATCH_SIZE = 25;
const CLOUD_SYNC_REFRESH_INTERVAL_MS = 60_000;
const CLOUD_SYNC_MIN_REQUEST_GAP_MS = 25_000;

export interface UseVaultItemListDataInput {
  readonly userId: string | null;
  readonly isDuressMode: boolean;
  /**
   * Ephemeral, in-memory decoy items rendered when `isDuressMode` is true.
   * `null` outside of duress mode. When in duress mode the data hook
   * returns these directly and skips every persistence-backed code path
   * (snapshot load, OpLog projection, integrity gate, decryption); duress
   * decoys are plaintext-by-design and never go near the database.
   */
  readonly duressDecoyItems: VaultItem[] | null;
  readonly useOpLogVerifiedRuntime: boolean;
  readonly opLogLocalVaultState: LocalVaultState | null;
  readonly refreshKey?: number;
  readonly vaultDataVersion: number;
  readonly decryptItem: (encrypted: string, itemId: string) => Promise<VaultItemData | null>;
  readonly decryptItemForLegacyMigration: (
    encrypted: string,
    itemId: string,
  ) => Promise<{ data: VaultItemData; legacyNoAadFallbackUsed: boolean }>;
  readonly encryptItem: (data: VaultItemData, entryId: string) => Promise<string>;
  readonly reportUnreadableItems: (items: QuarantinedVaultItem[]) => void;
  readonly verifyIntegrity: (...args: unknown[]) => Promise<VaultItemListIntegrityGate | null>;
  readonly refreshIntegrityBaseline: () => Promise<unknown>;
  readonly opLogUiRefresh: () => Promise<unknown>;
}

export interface UseVaultItemListDataResult {
  items: VaultItem[];
  setItems: React.Dispatch<React.SetStateAction<VaultItem[]>>;
  loading: boolean;
  decrypting: boolean;
  backgroundSyncing: boolean;
  lastCloudSyncAt: Date | null;
  revalidating: boolean;
  revalidateRemoteIntegrity: () => Promise<void>;
}

export function useVaultItemListData({
  userId,
  isDuressMode,
  duressDecoyItems,
  useOpLogVerifiedRuntime,
  opLogLocalVaultState,
  refreshKey,
  vaultDataVersion,
  decryptItem,
  decryptItemForLegacyMigration,
  encryptItem,
  reportUnreadableItems,
  verifyIntegrity,
  refreshIntegrityBaseline,
  opLogUiRefresh,
}: UseVaultItemListDataInput): UseVaultItemListDataResult {
  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const [backgroundSyncing, setBackgroundSyncing] = useState(false);
  const [lastCloudSyncAt, setLastCloudSyncAt] = useState<Date | null>(null);
  const [cloudSyncTick, setCloudSyncTick] = useState(0);
  const [revalidating, setRevalidating] = useState(false);

  // Mutable refs let the long-running fetch effect read the latest context
  // callbacks without resubscribing every render. Without these, the effect
  // would tear down its in-flight work on every parent rerender.
  const decryptItemRef = useRef(decryptItem);
  const decryptItemForLegacyMigrationRef = useRef(decryptItemForLegacyMigration);
  const encryptItemRef = useRef(encryptItem);
  const reportUnreadableItemsRef = useRef(reportUnreadableItems);
  const verifyIntegrityRef = useRef(verifyIntegrity);
  const refreshIntegrityBaselineRef = useRef(refreshIntegrityBaseline);

  useEffect(() => {
    decryptItemRef.current = decryptItem;
    decryptItemForLegacyMigrationRef.current = decryptItemForLegacyMigration;
    encryptItemRef.current = encryptItem;
    reportUnreadableItemsRef.current = reportUnreadableItems;
    verifyIntegrityRef.current = verifyIntegrity;
    refreshIntegrityBaselineRef.current = refreshIntegrityBaseline;
  }, [
    decryptItem,
    decryptItemForLegacyMigration,
    encryptItem,
    refreshIntegrityBaseline,
    reportUnreadableItems,
    verifyIntegrity,
  ]);

  const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
  const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());
  const fetchItemsRef = useRef(false);
  const pendingFetchItemsRef = useRef(false);
  const hasRenderedVaultContentRef = useRef(false);
  const opLogCloudSyncRef = useRef(false);
  const lastCloudSyncRequestAtRef = useRef(0);
  const revalidationRequestIdRef = useRef(0);
  const revalidatingRef = useRef(false);

  // Reset decrypt caches and "have we rendered anything yet?" flag whenever the
  // identity of the active vault changes. Without this a duress switch could
  // reuse stale negative decrypt cache entries and hide newly visible items.
  useEffect(() => {
    failedDecryptPayloadByItemIdRef.current.clear();
    loggedDecryptFailuresRef.current.clear();
    hasRenderedVaultContentRef.current = false;
    setLastCloudSyncAt(null);
    setBackgroundSyncing(false);
  }, [userId, isDuressMode]);

  // Cloud-sync trigger: bump `cloudSyncTick` on focus/visibility/online and at
  // a coarse interval. The actual fetch is gated below by the runtime flag.
  useEffect(() => {
    if (!userId) {
      return undefined;
    }

    const requestCloudSync = (options?: { force?: boolean }) => {
      if (!isAppOnline()) {
        return;
      }

      const now = Date.now();
      if (!options?.force && now - lastCloudSyncRequestAtRef.current < CLOUD_SYNC_MIN_REQUEST_GAP_MS) {
        return;
      }

      lastCloudSyncRequestAtRef.current = now;
      setCloudSyncTick((tick) => tick + 1);
    };

    const requestVisibleCloudSync = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return;
      }

      requestCloudSync();
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        requestCloudSync();
      }
    };

    const handleOnline = () => requestCloudSync({ force: true });

    window.addEventListener('focus', requestVisibleCloudSync);
    window.addEventListener('online', handleOnline);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    const intervalId = window.setInterval(requestVisibleCloudSync, CLOUD_SYNC_REFRESH_INTERVAL_MS);

    return () => {
      window.removeEventListener('focus', requestVisibleCloudSync);
      window.removeEventListener('online', handleOnline);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.clearInterval(intervalId);
    };
  }, [userId]);

  const revalidateRemoteIntegrity = useCallback(async () => {
    // Duress vault has no server manifest — running a real integrity check
    // would always resolve to integrity_unknown and block the panic vault.
    if (!userId || revalidatingRef.current || useOpLogVerifiedRuntime || isDuressMode) {
      return;
    }

    const requestId = revalidationRequestIdRef.current + 1;
    revalidationRequestIdRef.current = requestId;
    revalidatingRef.current = true;
    setRevalidating(true);
    try {
      await verifyIntegrityRef.current();
    } finally {
      if (revalidationRequestIdRef.current === requestId) {
        revalidatingRef.current = false;
        setRevalidating(false);
      }
    }
  }, [useOpLogVerifiedRuntime, userId]);

  // OpLog-verified runtime uses `opLogUiRefresh` for cloud sync. A separate
  // effect avoids contention with the snapshot-based path below.
  useEffect(() => {
    if (!useOpLogVerifiedRuntime || !userId || cloudSyncTick === 0 || !isAppOnline()) {
      return;
    }

    if (opLogCloudSyncRef.current) {
      return;
    }

    opLogCloudSyncRef.current = true;
    setBackgroundSyncing(true);

    void opLogUiRefresh()
      .then(() => {
        setLastCloudSyncAt(new Date());
      })
      .finally(() => {
        opLogCloudSyncRef.current = false;
        setBackgroundSyncing(false);
      });
  }, [cloudSyncTick, opLogUiRefresh, useOpLogVerifiedRuntime, userId]);

  useEffect(() => {
    async function fetchItems() {
      if (!userId) return;
      if (fetchItemsRef.current) {
        pendingFetchItemsRef.current = true;
        return;
      }

      const isBackgroundSync = hasRenderedVaultContentRef.current;
      fetchItemsRef.current = true;
      if (isBackgroundSync) {
        setBackgroundSyncing(true);
      } else {
        setLoading(true);
        setDecrypting(false);
      }
      try {
        // Duress (panic) vault: short-circuit every persistence-backed
        // path. The decoy items are already plaintext and ephemeral, so
        // the snapshot, OpLog projection, integrity gate and
        // legacy-migration code paths must be bypassed entirely. Running
        // them with the duress key would just produce a flood of
        // decryption failures and quarantined items — there is no real
        // ciphertext to decrypt against the duress key, by design. Note
        // that the data hook still fully resets on `(userId, isDuressMode)`
        // changes via the cleanup effect above, so toggling between real
        // and duress vaults cannot leak items in either direction.
        if (isDuressMode) {
          reportUnreadableItemsRef.current([]);
          setItems(duressDecoyItems ?? []);
          hasRenderedVaultContentRef.current = true;
          setLastCloudSyncAt(new Date());
          fetchItemsRef.current = false;
          setLoading(false);
          setDecrypting(false);
          setBackgroundSyncing(false);
          return;
        }

        if (useOpLogVerifiedRuntime) {
          const opLogItems = opLogLocalVaultState
            ? Array.from(opLogLocalVaultState.recordsById.values())
              .map(mapOpLogRecordToVaultItem)
              .filter((item): item is VaultItem => item !== null)
              .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
            : [];

          reportUnreadableItemsRef.current([]);
          setItems(opLogItems);
          hasRenderedVaultContentRef.current = true;
          setLastCloudSyncAt(new Date());
          fetchItemsRef.current = false;
          setLoading(false);
          setDecrypting(false);

          if (pendingFetchItemsRef.current) {
            pendingFetchItemsRef.current = false;
            void fetchItems();
          }

          return;
        }

        const { snapshot, source } = await loadVaultSnapshot(userId);
        const integrityResult: VaultItemListIntegrityGate | null = await verifyIntegrityRef.current(snapshot, { source });
        const allowsAnyDecrypt = integrityResult?.mode === 'healthy' || integrityResult?.mode === 'quarantine';
        if (!allowsAnyDecrypt) {
          setItems([]);
        } else {
          const canPersistMigrations = !useOpLogVerifiedRuntime
            && integrityResult?.mode === 'healthy'
            && integrityResult.isFirstCheck
            && source === 'remote'
            && isAppOnline();
          const canPersistLegacyEncryptionMigration = !useOpLogVerifiedRuntime
            && source === 'remote'
            && isAppOnline()
            && (
              integrityResult?.mode === 'healthy'
              || (
                integrityResult?.mode === 'quarantine'
                && integrityResult.quarantinedItems.length > 0
                && integrityResult.quarantinedItems.every((item) => item.reason === 'decrypt_failed')
              )
            );

          const vaultItems = [...snapshot.items].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
          let integrityBaselineDirty = false;
          const trustedItemIds = new Set<string>();
          const decryptableItemIds = new Set<string>();
          const unreadableItems: QuarantinedVaultItem[] = [];

          if (vaultItems.length > 0) {
            setDecrypting(true);
          }

          const decryptedItems = await mapInBatches(
            vaultItems,
            DECRYPT_BATCH_SIZE,
            async (item) => {
              if (!canDecryptFromIntegrityResult(integrityResult, item.id)) {
                return { ...item, decryptedData: undefined };
              }

              const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
              if (cachedFailedPayload === item.encrypted_data) {
                return { ...item, decryptedData: undefined };
              }

              let decryptedData: VaultItemData | null = null;
              try {
                decryptedData = await decryptItemRef.current(item.encrypted_data, item.id);
              } catch {
                if (canPersistLegacyEncryptionMigration) {
                  let legacyMigrationDecrypt: Awaited<ReturnType<typeof decryptItemForLegacyMigrationRef.current>> | null = null;
                  try {
                    legacyMigrationDecrypt = await decryptItemForLegacyMigrationRef.current(
                      item.encrypted_data,
                      item.id,
                    );
                    if (!legacyMigrationDecrypt.legacyNoAadFallbackUsed) {
                      throw new Error('No legacy encryption migration required.');
                    }
                  } catch {
                    legacyMigrationDecrypt = null;
                  }

                  if (legacyMigrationDecrypt) {
                    try {
                      const migration = await migrateLegacyVaultItemEncryptionAndMetadata({
                        userId,
                        vaultId: snapshot.vaultId,
                        item,
                        decryptedData: legacyMigrationDecrypt.data,
                        canPersistRemote: true,
                        encryptItem: encryptItemRef.current,
                      });
                      integrityBaselineDirty = true;
                      trustedItemIds.add(item.id);
                      decryptableItemIds.add(item.id);
                      failedDecryptPayloadByItemIdRef.current.delete(item.id);

                      return {
                        ...migration.item,
                        decryptedData: migration.decryptedData,
                      };
                    } catch (migrationError) {
                      if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                        console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                        decryptableItemIds.add(item.id);
                        failedDecryptPayloadByItemIdRef.current.delete(item.id);
                        return {
                          ...item,
                          decryptedData: legacyMigrationDecrypt.data,
                        };
                      }
                      throw migrationError;
                    }
                  }
                }

                failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
                unreadableItems.push({
                  id: item.id,
                  reason: 'decrypt_failed',
                  updatedAt: item.updated_at ?? null,
                  itemType: item.item_type ?? null,
                });
                const logKey = `${item.id}:${item.updated_at}`;
                if (!loggedDecryptFailuresRef.current.has(logKey)) {
                  loggedDecryptFailuresRef.current.add(logKey);
                  console.debug(
                    isDuressMode
                      ? 'Failed to decrypt item in Duress Mode (expected for Real items):'
                      : 'Failed to decrypt item (key mismatch or corrupt):',
                    item.id,
                  );
                }

                return { ...item, decryptedData: undefined };
              }
              if (!decryptedData) {
                throw new Error('Vault item decrypt returned no data.');
              }

              decryptableItemIds.add(item.id);
              failedDecryptPayloadByItemIdRef.current.delete(item.id);

              const migration = await migrateLegacyVaultItemMetadata({
                userId,
                vaultId: snapshot.vaultId,
                item,
                decryptedData,
                canPersistRemote: canPersistMigrations,
                encryptItem: encryptItemRef.current,
              });
              if (migration.migrated) {
                integrityBaselineDirty = true;
                trustedItemIds.add(item.id);
              }

              if (canPersistLegacyEncryptionMigration && !isVaultItemEnvelopeV2(migration.item.encrypted_data)) {
                try {
                  const encryptionMigration = await migrateLegacyVaultItemEncryptionAndMetadata({
                    userId,
                    vaultId: snapshot.vaultId,
                    item: migration.item,
                    decryptedData: migration.decryptedData,
                    canPersistRemote: true,
                    encryptItem: encryptItemRef.current,
                  });
                  integrityBaselineDirty = true;
                  trustedItemIds.add(item.id);
                  decryptableItemIds.add(item.id);
                  failedDecryptPayloadByItemIdRef.current.delete(item.id);

                  return {
                    ...encryptionMigration.item,
                    decryptedData: encryptionMigration.decryptedData,
                  };
                } catch (migrationError) {
                  if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                    console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                    return {
                      ...migration.item,
                      decryptedData: migration.decryptedData,
                    };
                  }
                  throw migrationError;
                }
              }

              return {
                ...migration.item,
                decryptedData: migration.decryptedData,
              };
            },
          );

          reportUnreadableItemsRef.current(unreadableItems);

          const canPersistTrustedFirstBaseline = integrityResult?.mode === 'healthy'
            && integrityResult.isFirstCheck
            && source === 'remote'
            && isAppOnline()
            && unreadableItems.length === 0;

          if (
            (integrityBaselineDirty && (canPersistMigrations || canPersistLegacyEncryptionMigration))
            || canPersistTrustedFirstBaseline
          ) {
            await refreshIntegrityBaselineRef.current();
          }

          setItems(decryptedItems as VaultItem[]);
          hasRenderedVaultContentRef.current = decryptedItems.length > 0
            || (integrityResult?.mode === 'quarantine' && integrityResult.quarantinedItems.length > 0);
          setLastCloudSyncAt(new Date());

          // Cached snapshots keep the vault usable offline and while local writes
          // are pending. A lightweight remote revalidation follows so DB-side
          // tampering can move items into quarantine without waiting for edit/open.
          if (!useOpLogVerifiedRuntime && source !== 'remote' && isAppOnline()) {
            void revalidateRemoteIntegrity();
          }
        }
      } catch (err) {
        console.error('Error fetching vault items:', err);
      } finally {
        fetchItemsRef.current = false;
      }

      if (pendingFetchItemsRef.current) {
        pendingFetchItemsRef.current = false;
        void fetchItems();
      } else {
        setLoading(false);
        setDecrypting(false);
        setBackgroundSyncing(false);
      }
    }

    void fetchItems();
  }, [
    refreshKey,
    cloudSyncTick,
    isDuressMode,
    duressDecoyItems,
    revalidateRemoteIntegrity,
    opLogLocalVaultState,
    useOpLogVerifiedRuntime,
    userId,
    vaultDataVersion,
  ]);

  return {
    items,
    setItems,
    loading,
    decrypting,
    backgroundSyncing,
    lastCloudSyncAt,
    revalidating,
    revalidateRemoteIntegrity,
  };
}
