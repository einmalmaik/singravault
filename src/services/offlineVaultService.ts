// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Offline vault cache + mutation queue service.
 *
 * Stores per-user vault snapshots in IndexedDB and queues offline mutations
 * for replay when connectivity returns.
 */

import { supabase } from '@/integrations/supabase/client';
import type { Database } from '@/integrations/supabase/types';

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];
type VaultItemInsert = Database['public']['Tables']['vault_items']['Insert'];
type CategoryRow = Database['public']['Tables']['categories']['Row'];
type CategoryInsert = Database['public']['Tables']['categories']['Insert'];

const DB_NAME = 'singra-offline-vault';
const DB_VERSION = 1;
const SNAPSHOTS_STORE = 'snapshots';
const MUTATIONS_STORE = 'mutations';
const MUTATIONS_USER_INDEX = 'by_user';

export interface OfflineVaultSnapshot {
  userId: string;
  vaultId: string | null;
  items: VaultItemRow[];
  categories: CategoryRow[];
  lastSyncedAt: string | null;
  updatedAt: string;
  // Credentials for offline unlock
  encryptionSalt?: string | null;
  masterPasswordVerifier?: string | null;
  kdfVersion?: number | null;
}

type OfflineMutation =
  | {
    id: string;
    userId: string;
    createdAt: string;
    type: 'upsert_item';
    payload: VaultItemInsert & { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    type: 'delete_item';
    payload: { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    type: 'upsert_category';
    payload: CategoryInsert & { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    type: 'delete_category';
    payload: { id: string };
  };

let dbPromise: Promise<IDBDatabase> | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

function sanitizeOptionalUuid(value: string | null | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (trimmed === '') return null;
  return trimmed;
}

function createEmptySnapshot(userId: string): OfflineVaultSnapshot {
  const now = nowIso();
  return {
    userId,
    vaultId: null,
    items: [],
    categories: [],
    lastSyncedAt: null,
    updatedAt: now,
  };
}

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;

  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;

      if (!db.objectStoreNames.contains(SNAPSHOTS_STORE)) {
        db.createObjectStore(SNAPSHOTS_STORE, { keyPath: 'userId' });
      }

      if (!db.objectStoreNames.contains(MUTATIONS_STORE)) {
        const store = db.createObjectStore(MUTATIONS_STORE, { keyPath: 'id' });
        store.createIndex(MUTATIONS_USER_INDEX, 'userId', { unique: false });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

  return dbPromise;
}

function withStore<T>(
  storeName: string,
  mode: IDBTransactionMode,
  handler: (store: IDBObjectStore, resolve: (value: T) => void, reject: (reason?: unknown) => void) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    openDb()
      .then((db) => {
        const tx = db.transaction(storeName, mode);
        const store = tx.objectStore(storeName);
        handler(store, resolve, reject);
      })
      .catch(reject);
  });
}

export function isLikelyOfflineError(error: unknown): boolean {
  if (!isAppOnline()) return true;
  const msg = String((error as { message?: string })?.message || '').toLowerCase();
  return (
    msg.includes('failed to fetch') ||
    msg.includes('network') ||
    msg.includes('fetch') ||
    msg.includes('load failed') ||
    msg.includes('xhr')
  );
}

export function isAppOnline(): boolean {
  return typeof navigator === 'undefined' ? true : navigator.onLine;
}

export function buildVaultItemRowFromInsert(insert: VaultItemInsert & { id: string }): VaultItemRow {
  const now = nowIso();
  return {
    id: insert.id,
    user_id: insert.user_id,
    vault_id: insert.vault_id,
    title: insert.title,
    website_url: insert.website_url ?? null,
    icon_url: insert.icon_url ?? null,
    item_type: (insert.item_type ?? 'password') as VaultItemRow['item_type'],
    encrypted_data: insert.encrypted_data,
    category_id: insert.category_id ?? null,
    is_favorite: insert.is_favorite ?? false,
    sort_order: insert.sort_order ?? null,
    last_used_at: insert.last_used_at ?? null,
    created_at: now,
    updated_at: now,
  };
}

export function buildCategoryRowFromInsert(insert: CategoryInsert & { id: string }): CategoryRow {
  const now = nowIso();
  return {
    id: insert.id,
    user_id: insert.user_id,
    name: insert.name,
    icon: insert.icon ?? null,
    color: insert.color ?? null,
    parent_id: insert.parent_id ?? null,
    sort_order: insert.sort_order ?? null,
    created_at: now,
    updated_at: now,
  };
}

export async function getOfflineSnapshot(userId: string): Promise<OfflineVaultSnapshot | null> {
  return withStore<OfflineVaultSnapshot | null>(SNAPSHOTS_STORE, 'readonly', (store, resolve, reject) => {
    const req = store.get(userId);
    req.onsuccess = () => resolve((req.result as OfflineVaultSnapshot | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function saveOfflineSnapshot(snapshot: OfflineVaultSnapshot): Promise<void> {
  await withStore<void>(SNAPSHOTS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.put(snapshot);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

/**
 * Saves encryption credentials for offline unlock.
 * Call this after successful vault setup or online profile fetch.
 */
export async function saveOfflineCredentials(
  userId: string,
  encryptionSalt: string,
  masterPasswordVerifier: string | null,
  kdfVersion?: number,
): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.encryptionSalt = encryptionSalt;
  snapshot.masterPasswordVerifier = masterPasswordVerifier;
  if (kdfVersion !== undefined) {
    snapshot.kdfVersion = kdfVersion;
  }
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

/**
 * Retrieves cached credentials for offline unlock.
 */
export async function getOfflineCredentials(
  userId: string,
): Promise<{ salt: string; verifier: string | null; kdfVersion: number | null } | null> {
  const snapshot = await getOfflineSnapshot(userId);
  if (!snapshot?.encryptionSalt) {
    return null;
  }
  return {
    salt: snapshot.encryptionSalt,
    verifier: snapshot.masterPasswordVerifier ?? null,
    kdfVersion: snapshot.kdfVersion ?? null,
  };
}

async function ensureSnapshot(userId: string): Promise<OfflineVaultSnapshot> {
  const existing = await getOfflineSnapshot(userId);
  return existing ?? createEmptySnapshot(userId);
}

export async function upsertOfflineItemRow(
  userId: string,
  row: VaultItemRow,
  vaultIdOverride?: string | null,
): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  const existing = snapshot.items.find((item) => item.id === row.id);
  const merged: VaultItemRow = {
    ...(existing ?? row),
    ...row,
    created_at: existing?.created_at ?? row.created_at ?? nowIso(),
    updated_at: row.updated_at ?? nowIso(),
  };

  snapshot.items = [merged, ...snapshot.items.filter((item) => item.id !== row.id)];
  snapshot.vaultId = vaultIdOverride ?? snapshot.vaultId ?? row.vault_id;
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

export async function removeOfflineItemRow(userId: string, itemId: string): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.items = snapshot.items.filter((item) => item.id !== itemId);
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

export async function upsertOfflineCategoryRow(userId: string, row: CategoryRow): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  const existing = snapshot.categories.find((cat) => cat.id === row.id);
  const merged: CategoryRow = {
    ...(existing ?? row),
    ...row,
    created_at: existing?.created_at ?? row.created_at ?? nowIso(),
    updated_at: row.updated_at ?? nowIso(),
  };

  snapshot.categories = [merged, ...snapshot.categories.filter((cat) => cat.id !== row.id)];
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

export async function removeOfflineCategoryRow(userId: string, categoryId: string): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.categories = snapshot.categories.filter((cat) => cat.id !== categoryId);
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

export async function enqueueOfflineMutation(
  mutation: Omit<OfflineMutation, 'id' | 'createdAt'>,
): Promise<string> {
  const id = crypto.randomUUID();
  const fullMutation = {
    ...mutation,
    id,
    createdAt: nowIso(),
  } as OfflineMutation;

  await withStore<void>(MUTATIONS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.put(fullMutation);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });

  return id;
}

export async function getOfflineMutations(userId: string): Promise<OfflineMutation[]> {
  return new Promise((resolve, reject) => {
    openDb()
      .then((db) => {
        const tx = db.transaction(MUTATIONS_STORE, 'readonly');
        const store = tx.objectStore(MUTATIONS_STORE);
        const index = store.index(MUTATIONS_USER_INDEX);
        const req = index.getAll(userId);
        req.onsuccess = () => {
          const entries = (req.result as OfflineMutation[]).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
          resolve(entries);
        };
        req.onerror = () => reject(req.error);
      })
      .catch(reject);
  });
}

export async function removeOfflineMutations(mutationIds: string[]): Promise<void> {
  if (mutationIds.length === 0) return;
  await withStore<void>(MUTATIONS_STORE, 'readwrite', (store, resolve, reject) => {
    mutationIds.forEach((id) => store.delete(id));
    resolve();
    store.transaction.onerror = () => reject(store.transaction.error);
  });
}

export async function resolveDefaultVaultId(userId: string): Promise<string | null> {
  if (isAppOnline()) {
    try {
      const { data, error } = await supabase
        .from('vaults')
        .select('id')
        .eq('user_id', userId)
        .eq('is_default', true)
        .order('created_at', { ascending: true })
        .limit(1);
      if (error) {
        throw error;
      }
      const resolvedVaultId = sanitizeOptionalUuid(data?.[0]?.id ?? null);
      if (resolvedVaultId) {
        const snapshot = await ensureSnapshot(userId);
        if (snapshot.vaultId !== resolvedVaultId) {
          snapshot.vaultId = resolvedVaultId;
          snapshot.updatedAt = nowIso();
          await saveOfflineSnapshot(snapshot);
        }
        return resolvedVaultId;
      }
    } catch (err) {
      if (!isLikelyOfflineError(err)) {
        throw err;
      }
    }
  }

  const snapshot = await getOfflineSnapshot(userId);
  return sanitizeOptionalUuid(snapshot?.vaultId ?? null);
}

export async function fetchRemoteOfflineSnapshot(userId: string): Promise<OfflineVaultSnapshot> {
  const { data: vault, error: vaultError } = await supabase
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .maybeSingle();

  if (vaultError && vaultError.code !== 'PGRST116') {
    throw vaultError;
  }

  const vaultId = sanitizeOptionalUuid(vault?.id ?? null);

  const { data: categories, error: categoriesError } = await supabase
    .from('categories')
    .select('*')
    .eq('user_id', userId)
    .order('sort_order', { ascending: true });

  if (categoriesError) {
    throw categoriesError;
  }

  let items: VaultItemRow[] = [];
  if (vaultId) {
    const { data: vaultItems, error: itemsError } = await supabase
      .from('vault_items')
      .select('*')
      .eq('vault_id', vaultId)
      .order('updated_at', { ascending: false });

    if (itemsError) {
      throw itemsError;
    }

    items = (vaultItems ?? []) as VaultItemRow[];
  }

  const now = nowIso();
  const snapshot: OfflineVaultSnapshot = {
    userId,
    vaultId,
    items,
    categories: (categories ?? []) as CategoryRow[],
    lastSyncedAt: now,
    updatedAt: now,
  };

  await saveOfflineSnapshot(snapshot);
  return snapshot;
}

export async function loadVaultSnapshot(userId: string): Promise<{
  snapshot: OfflineVaultSnapshot;
  source: 'remote' | 'cache' | 'empty';
}> {
  if (isAppOnline()) {
    try {
      const snapshot = await fetchRemoteOfflineSnapshot(userId);
      return { snapshot, source: 'remote' };
    } catch (err) {
      if (!isLikelyOfflineError(err)) {
        throw err;
      }
    }
  }

  const cached = await getOfflineSnapshot(userId);
  if (cached) {
    return { snapshot: cached, source: 'cache' };
  }

  return { snapshot: createEmptySnapshot(userId), source: 'empty' };
}

export async function syncOfflineMutations(userId: string): Promise<{
  processed: number;
  remaining: number;
  errors: number;
}> {
  const queue = await getOfflineMutations(userId);
  if (queue.length === 0 || !isAppOnline()) {
    return { processed: 0, remaining: queue.length, errors: 0 };
  }

  const successfulIds: string[] = [];
  let errors = 0;

  for (const mutation of queue) {
    try {
      if (mutation.type === 'upsert_item') {
        const { error } = await supabase
          .from('vault_items')
          .upsert(mutation.payload, { onConflict: 'id' });
        if (error) throw error;
      } else if (mutation.type === 'delete_item') {
        const { error } = await supabase
          .from('vault_items')
          .delete()
          .eq('id', mutation.payload.id);
        if (error) throw error;
      } else if (mutation.type === 'upsert_category') {
        const { error } = await supabase
          .from('categories')
          .upsert(mutation.payload, { onConflict: 'id' });
        if (error) throw error;
      } else if (mutation.type === 'delete_category') {
        const { error } = await supabase
          .from('categories')
          .delete()
          .eq('id', mutation.payload.id);
        if (error) throw error;
      }

      successfulIds.push(mutation.id);
    } catch (err) {
      if (isLikelyOfflineError(err)) {
        break;
      }
      errors += 1;
      break;
    }
  }

  await removeOfflineMutations(successfulIds);

  if (successfulIds.length > 0) {
    try {
      await fetchRemoteOfflineSnapshot(userId);
    } catch (err) {
      if (!isLikelyOfflineError(err)) {
        console.error('Failed to refresh snapshot after sync:', err);
      }
    }
  }

  const remaining = (await getOfflineMutations(userId)).length;
  return { processed: successfulIds.length, remaining, errors };
}
