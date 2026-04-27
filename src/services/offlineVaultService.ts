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
import { isTauriDevUserId, TAURI_DEV_VAULT_ID } from '@/platform/tauriDevMode';

type VaultItemRow = Database['public']['Tables']['vault_items']['Row'];
type VaultItemInsert = Database['public']['Tables']['vault_items']['Insert'];
type CategoryRow = Database['public']['Tables']['categories']['Row'];
type CategoryInsert = Database['public']['Tables']['categories']['Insert'];

const DB_NAME = 'singra-offline-vault';
const DB_VERSION = 2;
const SNAPSHOTS_STORE = 'snapshots';
const TRUSTED_SNAPSHOTS_STORE = 'trusted-snapshots';
const MUTATIONS_STORE = 'mutations';
const MUTATIONS_USER_INDEX = 'by_user';
// Keeps legitimate local writes authoritative while follow-up reads and remote
// replication settle. The window is scoped to the exact changed row IDs.
const LOCAL_WRITE_CACHE_TTL_MS = 60_000;

interface RecentLocalMutationWindow {
  freshUntil: number;
  itemIds: Set<string>;
  categoryIds: Set<string>;
}

const recentLocalMutationsByUser = new Map<string, RecentLocalMutationWindow>();

export interface OfflineVaultSnapshot {
  userId: string;
  vaultId: string | null;
  items: VaultItemRow[];
  categories: CategoryRow[];
  lastSyncedAt: string | null;
  updatedAt: string;
  /**
   * Monotonic server-maintained vault revision observed during the last trusted
   * online sync. Used only as a local rollback/stale-read checkpoint.
   */
  remoteRevision?: number | null;
  // Credentials for offline unlock
  encryptionSalt?: string | null;
  masterPasswordVerifier?: string | null;
  kdfVersion?: number | null;
  /** Encrypted UserKey (profiles.encrypted_user_key) for USK-based offline unlock */
  encryptedUserKey?: string | null;
  /**
   * Last online vault-unlock 2FA requirement. null/undefined means unknown,
   * which must fail closed while offline.
   */
  vaultTwoFactorRequired?: boolean | null;
}

type OfflineMutation =
  | {
    id: string;
    userId: string;
    createdAt: string;
    baseRemoteRevision?: number | null;
    type: 'upsert_item';
    payload: VaultItemInsert & { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    baseRemoteRevision?: number | null;
    type: 'delete_item';
    payload: { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    baseRemoteRevision?: number | null;
    type: 'upsert_category';
    payload: CategoryInsert & { id: string };
  }
  | {
    id: string;
    userId: string;
    createdAt: string;
    baseRemoteRevision?: number | null;
    type: 'delete_category';
    payload: { id: string };
  };

let dbPromise: Promise<IDBDatabase> | null = null;

function nowIso(): string {
  return new Date().toISOString();
}

function markLocalSnapshotFresh(
  userId: string,
  mutation: { itemId?: string; categoryId?: string },
): void {
  const current = recentLocalMutationsByUser.get(userId);
  const next: RecentLocalMutationWindow = {
    freshUntil: Date.now() + LOCAL_WRITE_CACHE_TTL_MS,
    itemIds: new Set(current?.itemIds),
    categoryIds: new Set(current?.categoryIds),
  };

  if (mutation.itemId) {
    next.itemIds.add(mutation.itemId);
  }

  if (mutation.categoryId) {
    next.categoryIds.add(mutation.categoryId);
  }

  recentLocalMutationsByUser.set(userId, next);
}

function getRecentLocalMutationWindow(userId: string): RecentLocalMutationWindow | null {
  const recent = recentLocalMutationsByUser.get(userId);
  if (!recent) {
    return null;
  }

  if (Date.now() <= recent.freshUntil) {
    return recent;
  }

  recentLocalMutationsByUser.delete(userId);
  return null;
}

export function isRecentLocalVaultMutation(
  userId: string,
  mutation: { itemIds?: Iterable<string>; categoryIds?: Iterable<string> },
): boolean {
  const itemIds = [...(mutation.itemIds ?? [])];
  const categoryIds = [...(mutation.categoryIds ?? [])];
  if (itemIds.length === 0 && categoryIds.length === 0) {
    return false;
  }

  const recent = getRecentLocalMutationWindow(userId);
  if (!recent) {
    return false;
  }

  return itemIds.every((itemId) => recent.itemIds.has(itemId))
    && categoryIds.every((categoryId) => recent.categoryIds.has(categoryId));
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
    vaultId: isTauriDevUserId(userId) ? TAURI_DEV_VAULT_ID : null,
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

      if (!db.objectStoreNames.contains(TRUSTED_SNAPSHOTS_STORE)) {
        db.createObjectStore(TRUSTED_SNAPSHOTS_STORE, { keyPath: 'userId' });
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

export function shouldUseLocalOnlyVault(userId: string | null | undefined): boolean {
  return isTauriDevUserId(userId);
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

function preserveLocalSecurityState(
  snapshot: OfflineVaultSnapshot,
  existing: OfflineVaultSnapshot | null,
): OfflineVaultSnapshot {
  if (!existing) {
    return snapshot;
  }

  return {
    ...snapshot,
    // Remote vault snapshots intentionally contain item/category data only.
    // Keep account-bound unlock metadata locally so PWA/Web reloads and
    // offline fallback cannot forget that a master password already exists.
    encryptionSalt: snapshot.encryptionSalt ?? existing.encryptionSalt,
    masterPasswordVerifier: snapshot.masterPasswordVerifier ?? existing.masterPasswordVerifier,
    kdfVersion: snapshot.kdfVersion ?? existing.kdfVersion,
    encryptedUserKey: snapshot.encryptedUserKey ?? existing.encryptedUserKey,
    vaultTwoFactorRequired: snapshot.vaultTwoFactorRequired ?? existing.vaultTwoFactorRequired,
    remoteRevision: snapshot.remoteRevision ?? existing.remoteRevision ?? null,
  };
}

export class OfflineSnapshotRollbackError extends Error {
  constructor(message = 'Remote vault snapshot is older than the local sync checkpoint.') {
    super(message);
    this.name = 'OfflineSnapshotRollbackError';
  }
}

async function fetchRemoteVaultRevision(vaultId: string | null): Promise<number | null> {
  if (!vaultId) {
    return null;
  }

  const { data, error } = await supabase.rpc(
    'get_vault_sync_head' as never,
    { p_vault_id: vaultId } as never,
  ) as unknown as {
    data: Array<{ revision: number | string | null }> | null;
    error: { code?: string; message?: string } | null;
  };

  if (error) {
    // Deployments without the sync-head migration should continue to work; they
    // simply do not get rollback detection until the migration is applied.
    if (error.code === 'PGRST202' || String(error.message ?? '').includes('get_vault_sync_head')) {
      return null;
    }
    throw error;
  }

  const rawRevision = data?.[0]?.revision;
  if (typeof rawRevision === 'number' && Number.isSafeInteger(rawRevision)) {
    return rawRevision;
  }

  if (typeof rawRevision === 'string' && /^\d+$/.test(rawRevision)) {
    const parsed = Number(rawRevision);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }

  return null;
}

function assertRemoteRevisionNotRolledBack(
  cachedSnapshot: OfflineVaultSnapshot | null,
  remoteRevision: number | null,
): void {
  const localRevision = cachedSnapshot?.remoteRevision;
  if (
    typeof localRevision === 'number'
    && typeof remoteRevision === 'number'
    && remoteRevision < localRevision
  ) {
    throw new OfflineSnapshotRollbackError();
  }
}

export async function removeOfflineSnapshot(userId: string): Promise<void> {
  await withStore<void>(SNAPSHOTS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.delete(userId);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function getTrustedOfflineSnapshot(userId: string): Promise<OfflineVaultSnapshot | null> {
  return withStore<OfflineVaultSnapshot | null>(TRUSTED_SNAPSHOTS_STORE, 'readonly', (store, resolve, reject) => {
    const req = store.get(userId);
    req.onsuccess = () => resolve((req.result as OfflineVaultSnapshot | undefined) ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function saveTrustedOfflineSnapshot(snapshot: OfflineVaultSnapshot): Promise<void> {
  await withStore<void>(TRUSTED_SNAPSHOTS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.put(snapshot);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export async function removeTrustedOfflineSnapshot(userId: string): Promise<void> {
  await withStore<void>(TRUSTED_SNAPSHOTS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.delete(userId);
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
  encryptedUserKey?: string | null,
): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.encryptionSalt = encryptionSalt;
  snapshot.masterPasswordVerifier = masterPasswordVerifier;
  if (kdfVersion !== undefined) {
    snapshot.kdfVersion = kdfVersion;
  }
  if (encryptedUserKey !== undefined) {
    snapshot.encryptedUserKey = encryptedUserKey;
  }
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

/**
 * Retrieves cached credentials for offline unlock.
 */
export async function getOfflineCredentials(
  userId: string,
): Promise<{ salt: string; verifier: string | null; kdfVersion: number | null; encryptedUserKey: string | null } | null> {
  const snapshot = await getOfflineSnapshot(userId);
  if (!snapshot?.encryptionSalt) {
    return null;
  }
  return {
    salt: snapshot.encryptionSalt,
    verifier: snapshot.masterPasswordVerifier ?? null,
    kdfVersion: snapshot.kdfVersion ?? null,
    encryptedUserKey: snapshot.encryptedUserKey ?? null,
  };
}

export async function saveOfflineVaultTwoFactorRequirement(
  userId: string,
  required: boolean,
): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.vaultTwoFactorRequired = required;
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
}

export async function getOfflineVaultTwoFactorRequirement(
  userId: string,
): Promise<boolean | null> {
  const snapshot = await getOfflineSnapshot(userId);
  return typeof snapshot?.vaultTwoFactorRequired === 'boolean'
    ? snapshot.vaultTwoFactorRequired
    : null;
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
  markLocalSnapshotFresh(userId, { itemId: row.id });
}

export async function removeOfflineItemRow(userId: string, itemId: string): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.items = snapshot.items.filter((item) => item.id !== itemId);
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
  markLocalSnapshotFresh(userId, { itemId });
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
  markLocalSnapshotFresh(userId, { categoryId: row.id });
}

export async function removeOfflineCategoryRow(userId: string, categoryId: string): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  snapshot.categories = snapshot.categories.filter((cat) => cat.id !== categoryId);
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
  markLocalSnapshotFresh(userId, { categoryId });
}

export async function applyOfflineCategoryDeletion(
  userId: string,
  categoryId: string,
  options: {
    updatedItems?: VaultItemRow[];
    deletedItemIds?: string[];
    vaultIdOverride?: string | null;
  } = {},
): Promise<void> {
  const snapshot = await ensureSnapshot(userId);
  const updatedItems = options.updatedItems ?? [];
  const updatedItemIds = new Set(updatedItems.map((item) => item.id));
  const deletedItemIds = new Set(options.deletedItemIds ?? []);

  snapshot.items = [
    ...updatedItems,
    ...snapshot.items.filter((item) => !updatedItemIds.has(item.id) && !deletedItemIds.has(item.id)),
  ];
  snapshot.categories = snapshot.categories.filter((cat) => cat.id !== categoryId);
  snapshot.vaultId = options.vaultIdOverride ?? snapshot.vaultId;
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);

  for (const itemId of new Set([...updatedItemIds, ...deletedItemIds])) {
    markLocalSnapshotFresh(userId, { itemId });
  }
  markLocalSnapshotFresh(userId, { categoryId });
}

export async function enqueueOfflineMutation(
  mutation: Omit<OfflineMutation, 'id' | 'createdAt'>,
): Promise<string> {
  const id = crypto.randomUUID();
  if (isTauriDevUserId(mutation.userId)) {
    return id;
  }

  const fullMutation = {
    ...mutation,
    id,
    createdAt: nowIso(),
    baseRemoteRevision: mutation.baseRemoteRevision
      ?? (await getOfflineSnapshot(mutation.userId))?.remoteRevision
      ?? null,
  } as OfflineMutation;

  await withStore<void>(MUTATIONS_STORE, 'readwrite', (store, resolve, reject) => {
    const req = store.put(fullMutation);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });

  return id;
}

interface AppliedVaultMutationResult {
  applied: boolean;
  revision: number | string | null;
  conflict_reason: string | null;
}

function normalizeRemoteRevision(value: number | string | null | undefined): number | null {
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }

  if (typeof value === 'string' && /^\d+$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  }

  return null;
}

async function applyQueuedVaultMutation(mutation: OfflineMutation): Promise<AppliedVaultMutationResult> {
  const { data, error } = await supabase.rpc(
    'apply_vault_mutation' as never,
    {
      p_base_revision: mutation.baseRemoteRevision ?? null,
      p_type: mutation.type,
      p_payload: mutation.payload,
    } as never,
  ) as unknown as {
    data: AppliedVaultMutationResult | null;
    error: { message?: string } | null;
  };

  if (error) {
    throw error;
  }

  return data ?? { applied: false, revision: null, conflict_reason: 'empty_result' };
}

async function updateCachedRemoteRevision(userId: string, revision: number | null): Promise<void> {
  if (revision === null) {
    return;
  }

  const snapshot = await ensureSnapshot(userId);
  if (typeof snapshot.remoteRevision === 'number' && revision < snapshot.remoteRevision) {
    throw new OfflineSnapshotRollbackError();
  }

  snapshot.remoteRevision = revision;
  snapshot.updatedAt = nowIso();
  await saveOfflineSnapshot(snapshot);
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

export async function clearOfflineMutations(userId: string): Promise<void> {
  const mutations = await getOfflineMutations(userId);
  await removeOfflineMutations(mutations.map((mutation) => mutation.id));
}

export async function resolveDefaultVaultId(userId: string): Promise<string | null> {
  if (isTauriDevUserId(userId)) {
    const snapshot = await ensureSnapshot(userId);
    if (snapshot.vaultId !== TAURI_DEV_VAULT_ID) {
      snapshot.vaultId = TAURI_DEV_VAULT_ID;
      snapshot.updatedAt = nowIso();
      await saveOfflineSnapshot(snapshot);
    }
    return TAURI_DEV_VAULT_ID;
  }

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

export async function fetchRemoteOfflineSnapshot(
  userId: string,
  options?: { persist?: boolean },
): Promise<OfflineVaultSnapshot> {
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
  const remoteSnapshot: OfflineVaultSnapshot = {
    userId,
    vaultId,
    items,
    categories: (categories ?? []) as CategoryRow[],
    lastSyncedAt: now,
    updatedAt: now,
  };
  const cachedSnapshot = await getOfflineSnapshot(userId);
  const remoteRevision = await fetchRemoteVaultRevision(vaultId);
  assertRemoteRevisionNotRolledBack(cachedSnapshot, remoteRevision);

  const snapshot = preserveLocalSecurityState(remoteSnapshot, cachedSnapshot);
  snapshot.remoteRevision = remoteRevision ?? cachedSnapshot?.remoteRevision ?? null;

  if (options?.persist !== false) {
    await saveOfflineSnapshot(snapshot);
  }
  return snapshot;
}

function applyRecentLocalMutations(
  remoteSnapshot: OfflineVaultSnapshot,
  cachedSnapshot: OfflineVaultSnapshot,
  recent: RecentLocalMutationWindow,
): OfflineVaultSnapshot {
  const itemsById = new Map(remoteSnapshot.items.map((item) => [item.id, item]));
  const cachedItemsById = new Map(cachedSnapshot.items.map((item) => [item.id, item]));
  for (const itemId of recent.itemIds) {
    const cachedItem = cachedItemsById.get(itemId);
    if (cachedItem) {
      itemsById.set(itemId, cachedItem);
    } else {
      itemsById.delete(itemId);
    }
  }

  const categoriesById = new Map(remoteSnapshot.categories.map((category) => [category.id, category]));
  const cachedCategoriesById = new Map(cachedSnapshot.categories.map((category) => [category.id, category]));
  for (const categoryId of recent.categoryIds) {
    const cachedCategory = cachedCategoriesById.get(categoryId);
    if (cachedCategory) {
      categoriesById.set(categoryId, cachedCategory);
    } else {
      categoriesById.delete(categoryId);
    }
  }

  return {
    ...remoteSnapshot,
    items: [...itemsById.values()],
    categories: [...categoriesById.values()],
    updatedAt: nowIso(),
    encryptionSalt: cachedSnapshot.encryptionSalt ?? remoteSnapshot.encryptionSalt,
    masterPasswordVerifier: cachedSnapshot.masterPasswordVerifier ?? remoteSnapshot.masterPasswordVerifier,
    kdfVersion: cachedSnapshot.kdfVersion ?? remoteSnapshot.kdfVersion,
    encryptedUserKey: cachedSnapshot.encryptedUserKey ?? remoteSnapshot.encryptedUserKey,
    vaultTwoFactorRequired: cachedSnapshot.vaultTwoFactorRequired ?? remoteSnapshot.vaultTwoFactorRequired,
    remoteRevision: remoteSnapshot.remoteRevision ?? cachedSnapshot.remoteRevision ?? null,
  };
}

export async function loadVaultSnapshot(userId: string): Promise<{
  snapshot: OfflineVaultSnapshot;
  source: 'remote' | 'cache' | 'empty';
}> {
  if (isTauriDevUserId(userId)) {
    const cached = await getOfflineSnapshot(userId);
    return cached
      ? { snapshot: cached, source: 'cache' }
      : { snapshot: createEmptySnapshot(userId), source: 'empty' };
  }

  if (isAppOnline()) {
    try {
      const pendingMutations = await getOfflineMutations(userId);
      if (pendingMutations.length > 0) {
        const cached = await getOfflineSnapshot(userId);
        if (cached) {
          return { snapshot: cached, source: 'cache' };
        }
      }

      const recent = getRecentLocalMutationWindow(userId);
      if (recent) {
        const cached = await getOfflineSnapshot(userId);
        if (cached) {
          const remoteSnapshot = await fetchRemoteOfflineSnapshot(userId, { persist: false });
          const mergedSnapshot = applyRecentLocalMutations(remoteSnapshot, cached, recent);
          await saveOfflineSnapshot(mergedSnapshot);
          return { snapshot: mergedSnapshot, source: 'cache' };
        }
      }

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

export async function clearOfflineVaultData(userId: string): Promise<void> {
  await Promise.all([
    removeOfflineSnapshot(userId),
    removeTrustedOfflineSnapshot(userId),
    clearOfflineMutations(userId),
  ]);
}

export async function syncOfflineMutations(userId: string): Promise<{
  processed: number;
  remaining: number;
  errors: number;
}> {
  if (isTauriDevUserId(userId)) {
    return { processed: 0, remaining: 0, errors: 0 };
  }

  const queue = await getOfflineMutations(userId);
  if (queue.length === 0 || !isAppOnline()) {
    return { processed: 0, remaining: queue.length, errors: 0 };
  }

  const successfulIds: string[] = [];
  let errors = 0;

  for (const mutation of queue) {
    try {
      const mutationResult = await applyQueuedVaultMutation(mutation);
      if (!mutationResult.applied) {
        errors += 1;
        break;
      }

      await updateCachedRemoteRevision(userId, normalizeRemoteRevision(mutationResult.revision));
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
