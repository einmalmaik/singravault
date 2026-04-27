// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Phase 3 — Unit tests for offlineVaultService.
 *
 * Covers IndexedDB-dependent functions (snapshot CRUD, credentials,
 * item/category row mutations, mutation queue) and Supabase-dependent
 * functions (resolveDefaultVaultId, fetchRemoteOfflineSnapshot,
 * loadVaultSnapshot, syncOfflineMutations).
 *
 * Pure helpers tested in Phase 1 are intentionally skipped.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ============================================================================
// In-memory IndexedDB mock
// ============================================================================

/**
 * Fully featured in-memory IndexedDB mock that supports objectStoreNames,
 * createObjectStore, createIndex, transaction, store CRUD, and index queries.
 *
 * Index metadata is persisted in FakeIDBDatabase._storeMeta so that indexes
 * created during onupgradeneeded survive across transaction boundaries.
 */

interface StoreMeta {
  keyPath: string;
  data: Map<string, unknown>;
  indexes: Map<string, string>; // indexName → keyPath
}

class FakeIDBIndex {
  constructor(
    private data: Map<string, unknown>,
    private indexField: string,
  ) { }

  getAll(key?: unknown): FakeIDBRequest {
    const results: unknown[] = [];
    for (const value of this.data.values()) {
      if (key === undefined || (value as Record<string, unknown>)[this.indexField] === key) {
        results.push(value);
      }
    }
    return new FakeIDBRequest(results);
  }
}

class FakeIDBObjectStore {
  constructor(
    private meta: StoreMeta,
    public transaction: FakeIDBTransaction,
  ) { }

  createIndex(name: string, keyPath: string, _options?: unknown): FakeIDBIndex {
    this.meta.indexes.set(name, keyPath);
    return new FakeIDBIndex(this.meta.data, keyPath);
  }

  index(name: string): FakeIDBIndex {
    const field = this.meta.indexes.get(name);
    if (field === undefined) {
      throw new DOMException(`Index "${name}" not found`, "NotFoundError");
    }
    return new FakeIDBIndex(this.meta.data, field);
  }

  get(key: unknown): FakeIDBRequest {
    return new FakeIDBRequest(this.meta.data.get(String(key)));
  }

  put(value: unknown): FakeIDBRequest {
    const key = (value as Record<string, unknown>)[this.meta.keyPath];
    this.meta.data.set(String(key), value);
    return new FakeIDBRequest(key);
  }

  delete(key: unknown): FakeIDBRequest {
    this.meta.data.delete(String(key));
    return new FakeIDBRequest(undefined);
  }
}

class FakeIDBTransaction {
  onerror: ((event: unknown) => void) | null = null;
  error: DOMException | null = null;

  constructor(private db: FakeIDBDatabase) { }

  objectStore(name: string): FakeIDBObjectStore {
    const meta = this.db._storeMeta.get(name);
    if (!meta) {
      throw new DOMException(`Object store "${name}" not found`, "NotFoundError");
    }
    return new FakeIDBObjectStore(meta, this);
  }
}

class FakeIDBRequest {
  result: unknown;
  error: DOMException | null = null;
  onsuccess: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;

  constructor(result: unknown) {
    this.result = result;
    // Trigger onsuccess asynchronously (microtask)
    Promise.resolve().then(() => {
      if (this.onsuccess) {
        this.onsuccess({ target: this });
      }
    });
  }
}

class FakeIDBDatabase {
  _storeMeta: Map<string, StoreMeta> = new Map();

  get objectStoreNames(): { contains: (name: string) => boolean } {
    const names = this._storeMeta;
    return { contains: (name: string) => names.has(name) };
  }

  createObjectStore(name: string, options?: { keyPath?: string }): FakeIDBObjectStore {
    const keyPath = options?.keyPath ?? "id";
    if (!this._storeMeta.has(name)) {
      this._storeMeta.set(name, { keyPath, data: new Map(), indexes: new Map() });
    }
    const meta = this._storeMeta.get(name)!;
    const tx = new FakeIDBTransaction(this);
    return new FakeIDBObjectStore(meta, tx);
  }

  transaction(storeNames: string | string[], _mode?: IDBTransactionMode): FakeIDBTransaction {
    return new FakeIDBTransaction(this);
  }
}

class FakeIDBOpenRequest {
  result: FakeIDBDatabase;
  error: DOMException | null = null;
  onsuccess: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onupgradeneeded: (() => void) | null = null;

  constructor(private db: FakeIDBDatabase, private triggerUpgrade: boolean) {
    this.result = db;
    Promise.resolve().then(() => {
      if (this.triggerUpgrade && this.onupgradeneeded) {
        this.onupgradeneeded();
      }
      if (this.onsuccess) {
        this.onsuccess({ target: this });
      }
    });
  }
}

/** Shared DB instance per test, reset via resetFakeIndexedDB(). */
let sharedFakeDb: FakeIDBDatabase;

function resetFakeIndexedDB() {
  sharedFakeDb = new FakeIDBDatabase();
}

function installFakeIndexedDB() {
  resetFakeIndexedDB();
  // The setup.ts mock defines window.indexedDB without configurable:true,
  // so we cannot redefine the property. Instead, we replace the methods
  // on the existing indexedDB object.
  const idb = globalThis.indexedDB as unknown as Record<string, unknown>;
  idb.open = (_name: string, _version?: number) => {
    return new FakeIDBOpenRequest(sharedFakeDb, true);
  };
  idb.deleteDatabase = () => new FakeIDBRequest(undefined);
}

// ============================================================================
// Supabase mock (chainable pattern from Phase 2)
// ============================================================================

function createChainable(resolvedValue: unknown = { data: null, error: null }) {
  const chain: Record<string, (...args: unknown[]) => unknown> = {};
  const methods = [
    "select", "insert", "update", "delete", "upsert",
    "eq", "in", "single", "maybeSingle", "limit", "order",
  ];
  for (const m of methods) {
    chain[m] = vi.fn().mockReturnValue(chain);
  }
  chain.then = (resolve: (v: unknown) => unknown) => resolve(resolvedValue);
  return chain;
}

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let chainIndex = 0;

  const fromImpl = () => {
    const idx = chainIndex++;
    return chains[idx] || createChainable();
  };

  return {
    from: vi.fn().mockImplementation(fromImpl),
    rpc: vi.fn(),
    auth: { getUser: vi.fn(), getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" } }, error: null }) },
    functions: { invoke: vi.fn() },
    storage: { from: vi.fn() },
    _setChains: (newChains: unknown[]) => {
      chains.length = 0;
      chains.push(...newChains);
      chainIndex = 0;
    },
    _reset: () => {
      chains.length = 0;
      chainIndex = 0;
    },
    _restoreFrom: () => {
      // vi.clearAllMocks() strips mockImplementation — restore it
      mockSupabase.from.mockImplementation(fromImpl);
    },
  };
});

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));

// ============================================================================
// Module import — must come AFTER mocks are wired
// ============================================================================

// We use vi.resetModules() + dynamic import to get a fresh module (and fresh
// dbPromise) for every test.
type OfflineService = typeof import("@/services/offlineVaultService");
let svc: OfflineService;

// Derived types from service function signatures
type VaultItemRow = Parameters<OfflineService["upsertOfflineItemRow"]>[1];
type CategoryRow = Parameters<OfflineService["upsertOfflineCategoryRow"]>[1];
type MutationInput = Parameters<OfflineService["enqueueOfflineMutation"]>[0];

// ============================================================================
// Helpers
// ============================================================================

const USER_ID = "user-abc-123";
const VAULT_ID = "vault-def-456";
const TAURI_DEV_USER_ID = "00000000-0000-4000-8000-000000000001";
const TAURI_DEV_VAULT_ID = "00000000-0000-4000-8000-000000000002";

function makeItemRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "item-1",
    user_id: USER_ID,
    vault_id: VAULT_ID,
    title: "My Login",
    website_url: null,
    icon_url: null,
    item_type: "password" as const,
    encrypted_data: "enc-payload",
    category_id: null,
    is_favorite: false,
    sort_order: null,
    last_used_at: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function makeCategoryRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "cat-1",
    user_id: USER_ID,
    name: "Social",
    icon: null,
    color: null,
    parent_id: null,
    sort_order: null,
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

// ============================================================================
// Setup / Teardown
// ============================================================================

beforeEach(async () => {
  vi.clearAllMocks();
  mockSupabase._reset();
  mockSupabase._restoreFrom();

  // Fresh IndexedDB for every test
  installFakeIndexedDB();

  // Reset module cache so dbPromise is null
  vi.resetModules();
  svc = await import("@/services/offlineVaultService");
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ============================================================================
// Snapshot Round-Trip
// ============================================================================

describe("Snapshot round-trip", () => {
  it("saveOfflineSnapshot → getOfflineSnapshot round-trips correctly", async () => {
    const snapshot = {
      userId: USER_ID,
      vaultId: VAULT_ID,
      items: [makeItemRow()],
      categories: [makeCategoryRow()],
      lastSyncedAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };

    await svc.saveOfflineSnapshot(snapshot);
    const loaded = await svc.getOfflineSnapshot(USER_ID);

    expect(loaded).toEqual(snapshot);
  });

  it("keeps note plaintext out of offline snapshots when callers provide encrypted_data rows", async () => {
    const privateNote = "offline snapshot must not contain this note";
    const snapshot = {
      userId: USER_ID,
      vaultId: VAULT_ID,
      items: [
        makeItemRow({
          item_type: "note",
          encrypted_data: "sv-vault-item-v1:ciphertext-without-note-plaintext",
        }),
      ],
      categories: [],
      lastSyncedAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };

    await svc.saveOfflineSnapshot(snapshot);
    const loaded = await svc.getOfflineSnapshot(USER_ID);

    expect(JSON.stringify(loaded)).not.toContain(privateNote);
    expect(loaded?.items[0]).toMatchObject({
      item_type: "note",
      encrypted_data: "sv-vault-item-v1:ciphertext-without-note-plaintext",
    });
  });

  it("getOfflineSnapshot returns null when nothing is saved", async () => {
    const loaded = await svc.getOfflineSnapshot("nonexistent-user");
    expect(loaded).toBeNull();
  });

  it("overwriting an existing snapshot replaces it entirely", async () => {
    const v1 = {
      userId: USER_ID,
      vaultId: VAULT_ID,
      items: [makeItemRow()],
      categories: [],
      lastSyncedAt: null,
      updatedAt: "2026-01-01T00:00:00.000Z",
    };

    await svc.saveOfflineSnapshot(v1);

    const v2 = {
      ...v1,
      items: [],
      categories: [makeCategoryRow()],
      updatedAt: "2026-02-01T00:00:00.000Z",
    };

    await svc.saveOfflineSnapshot(v2);
    const loaded = await svc.getOfflineSnapshot(USER_ID);

    expect(loaded).toEqual(v2);
    expect(loaded!.items).toHaveLength(0);
    expect(loaded!.categories).toHaveLength(1);
  });
});

// ============================================================================
// Credentials
// ============================================================================

describe("Offline credentials", () => {
  it("saveOfflineCredentials → getOfflineCredentials round-trips", async () => {
    await svc.saveOfflineCredentials(USER_ID, "salt-abc", "verifier-xyz", 2);

    const creds = await svc.getOfflineCredentials(USER_ID);
    expect(creds).toEqual({ salt: "salt-abc", verifier: "verifier-xyz", kdfVersion: 2, encryptedUserKey: null });
  });

  it("saveOfflineCredentials without kdfVersion returns null kdfVersion", async () => {
    await svc.saveOfflineCredentials(USER_ID, "salt-abc", "verifier-xyz");

    const creds = await svc.getOfflineCredentials(USER_ID);
    expect(creds).toEqual({ salt: "salt-abc", verifier: "verifier-xyz", kdfVersion: null, encryptedUserKey: null });
  });

  it("getOfflineCredentials returns null when not saved", async () => {
    const creds = await svc.getOfflineCredentials("no-such-user");
    expect(creds).toBeNull();
  });

  it("stores salt and verifier (not the raw key)", async () => {
    await svc.saveOfflineCredentials(USER_ID, "my-salt", "my-verifier");

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot).not.toBeNull();
    expect(snapshot!.encryptionSalt).toBe("my-salt");
    expect(snapshot!.masterPasswordVerifier).toBe("my-verifier");
    // Ensure no raw key field exists
    expect(snapshot).not.toHaveProperty("masterKey");
    expect(snapshot).not.toHaveProperty("encryptionKey");
  });

  it("saveOfflineVaultTwoFactorRequirement round-trips and survives credential updates", async () => {
    await svc.saveOfflineVaultTwoFactorRequirement(USER_ID, false);
    await svc.saveOfflineCredentials(USER_ID, "salt-abc", "verifier-xyz", 2);

    await expect(svc.getOfflineVaultTwoFactorRequirement(USER_ID)).resolves.toBe(false);
    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot?.vaultTwoFactorRequired).toBe(false);
  });
});

// ============================================================================
// Item Row Mutations
// ============================================================================

describe("Item row mutations", () => {
  it("upsertOfflineItemRow adds an item to the snapshot", async () => {
    const row = makeItemRow();
    await svc.upsertOfflineItemRow(USER_ID, row as VaultItemRow);

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot).not.toBeNull();
    expect(snapshot!.items).toHaveLength(1);
    expect(snapshot!.items[0].id).toBe("item-1");
  });

  it("upsertOfflineItemRow updates an existing item", async () => {
    const row = makeItemRow();
    await svc.upsertOfflineItemRow(USER_ID, row as VaultItemRow);

    const updated = makeItemRow({ title: "Updated Login", updated_at: "2026-06-01T00:00:00.000Z" });
    await svc.upsertOfflineItemRow(USER_ID, updated as VaultItemRow);

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot!.items).toHaveLength(1);
    expect(snapshot!.items[0].title).toBe("Updated Login");
    // Preserves original created_at
    expect(snapshot!.items[0].created_at).toBe("2026-01-01T00:00:00.000Z");
  });

  it("removeOfflineItemRow removes the item", async () => {
    const row = makeItemRow();
    await svc.upsertOfflineItemRow(USER_ID, row as VaultItemRow);

    await svc.removeOfflineItemRow(USER_ID, "item-1");

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot!.items).toHaveLength(0);
  });
});

// ============================================================================
// Category Row Mutations
// ============================================================================

describe("Category row mutations", () => {
  it("upsertOfflineCategoryRow adds a category to the snapshot", async () => {
    const row = makeCategoryRow();
    await svc.upsertOfflineCategoryRow(USER_ID, row as CategoryRow);

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot).not.toBeNull();
    expect(snapshot!.categories).toHaveLength(1);
    expect(snapshot!.categories[0].id).toBe("cat-1");
  });

  it("upsertOfflineCategoryRow updates an existing category", async () => {
    const row = makeCategoryRow();
    await svc.upsertOfflineCategoryRow(USER_ID, row as CategoryRow);

    const updated = makeCategoryRow({ name: "Work", updated_at: "2026-06-01T00:00:00.000Z" });
    await svc.upsertOfflineCategoryRow(USER_ID, updated as CategoryRow);

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot!.categories).toHaveLength(1);
    expect(snapshot!.categories[0].name).toBe("Work");
    expect(snapshot!.categories[0].created_at).toBe("2026-01-01T00:00:00.000Z");
  });

  it("removeOfflineCategoryRow removes the category", async () => {
    const row = makeCategoryRow();
    await svc.upsertOfflineCategoryRow(USER_ID, row as CategoryRow);

    await svc.removeOfflineCategoryRow(USER_ID, "cat-1");

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot!.categories).toHaveLength(0);
  });

  it("applyOfflineCategoryDeletion updates items and removes the category in one cached snapshot", async () => {
    await svc.upsertOfflineCategoryRow(USER_ID, makeCategoryRow() as CategoryRow);
    await svc.upsertOfflineItemRow(USER_ID, makeItemRow({ id: "item-1", category_id: "cat-1" }) as VaultItemRow);
    await svc.upsertOfflineItemRow(USER_ID, makeItemRow({ id: "item-2", category_id: "cat-1" }) as VaultItemRow);

    await svc.applyOfflineCategoryDeletion(USER_ID, "cat-1", {
      updatedItems: [
        makeItemRow({ id: "item-1", category_id: null, encrypted_data: "updated-ciphertext" }) as VaultItemRow,
      ],
      deletedItemIds: ["item-2"],
    });

    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot!.categories).toHaveLength(0);
    expect(snapshot!.items.map((item) => item.id)).toEqual(["item-1"]);
    expect(snapshot!.items[0].category_id).toBeNull();
    expect(snapshot!.items[0].encrypted_data).toBe("updated-ciphertext");
    expect(svc.isRecentLocalVaultMutation(USER_ID, {
      itemIds: ["item-1", "item-2"],
      categoryIds: ["cat-1"],
    })).toBe(true);
  });

  it("tracks recently changed local category rows in memory", async () => {
    await svc.upsertOfflineCategoryRow(USER_ID, makeCategoryRow() as CategoryRow);

    expect(svc.isRecentLocalVaultMutation(USER_ID, { categoryIds: ["cat-1"] })).toBe(true);
    expect(svc.isRecentLocalVaultMutation(USER_ID, { categoryIds: ["cat-other"] })).toBe(false);
    expect(svc.isRecentLocalVaultMutation(USER_ID, {})).toBe(false);
  });
});

// ============================================================================
// Mutation Queue
// ============================================================================

describe("Mutation queue", () => {
  it("enqueueOfflineMutation adds a mutation", async () => {
    const id = await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_item",
      payload: { id: "item-1", user_id: USER_ID, vault_id: VAULT_ID, title: "Test", encrypted_data: "enc" },
    } as MutationInput);

    expect(typeof id).toBe("string");
    expect(id.length).toBeGreaterThan(0);

    const mutations = await svc.getOfflineMutations(USER_ID);
    expect(mutations).toHaveLength(1);
    expect(mutations[0].type).toBe("upsert_item");
    expect(mutations[0].id).toBe(id);
  });

  it("tauri dev user: does not queue local-only mutations", async () => {
    const id = await svc.enqueueOfflineMutation({
      userId: TAURI_DEV_USER_ID,
      type: "upsert_category",
      payload: { id: "cat-1", user_id: TAURI_DEV_USER_ID, name: "enc:cat:v1:dev" },
    } as MutationInput);

    expect(typeof id).toBe("string");
    await expect(svc.getOfflineMutations(TAURI_DEV_USER_ID)).resolves.toEqual([]);
  });

  it("getOfflineMutations returns entries sorted by createdAt", async () => {
    // Enqueue with small delays so createdAt values differ
    const id1 = await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_item",
      payload: { id: "item-1", user_id: USER_ID, vault_id: VAULT_ID, title: "First", encrypted_data: "e1" },
    } as MutationInput);

    // Force a later timestamp
    vi.spyOn(Date.prototype, "toISOString")
      .mockReturnValueOnce("2026-12-31T23:59:59.000Z");

    const id2 = await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "delete_item",
      payload: { id: "item-2" },
    } as MutationInput);

    const mutations = await svc.getOfflineMutations(USER_ID);
    expect(mutations).toHaveLength(2);
    // First enqueued should come before the second (sorted by createdAt ascending)
    expect(mutations[0].id).toBe(id1);
    expect(mutations[1].id).toBe(id2);
  });

  it("removeOfflineMutations removes specific IDs", async () => {
    const id1 = await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_item",
      payload: { id: "item-1", user_id: USER_ID, vault_id: VAULT_ID, title: "A", encrypted_data: "e" },
    } as MutationInput);

    const id2 = await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "delete_item",
      payload: { id: "item-2" },
    } as MutationInput);

    await svc.removeOfflineMutations([id1]);

    const remaining = await svc.getOfflineMutations(USER_ID);
    expect(remaining).toHaveLength(1);
    expect(remaining[0].id).toBe(id2);
  });

  it("empty queue returns empty array", async () => {
    const mutations = await svc.getOfflineMutations(USER_ID);
    expect(mutations).toEqual([]);
  });
});

// ============================================================================
// resolveDefaultVaultId
// ============================================================================

describe("resolveDefaultVaultId", () => {
  it("online: fetches vault ID from Supabase and caches it", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    const chain = createChainable({ data: [{ id: VAULT_ID }], error: null });
    mockSupabase._setChains([chain]);

    const result = await svc.resolveDefaultVaultId(USER_ID);
    expect(result).toBe(VAULT_ID);
    expect(mockSupabase.from).toHaveBeenCalledWith("vaults");

    // Should be cached in snapshot
    const snapshot = await svc.getOfflineSnapshot(USER_ID);
    expect(snapshot?.vaultId).toBe(VAULT_ID);
  });

  it("offline: uses cached vault ID from snapshot", async () => {
    // Pre-seed snapshot with a vault ID
    await svc.saveOfflineSnapshot({
      userId: USER_ID,
      vaultId: VAULT_ID,
      items: [],
      categories: [],
      lastSyncedAt: null,
      updatedAt: "2026-01-01T00:00:00.000Z",
    });

    Object.defineProperty(navigator, "onLine", { value: false, configurable: true });

    const result = await svc.resolveDefaultVaultId(USER_ID);
    expect(result).toBe(VAULT_ID);
    // Should NOT have called Supabase
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it("returns null when both online query and cache fail", async () => {
    Object.defineProperty(navigator, "onLine", { value: false, configurable: true });

    const result = await svc.resolveDefaultVaultId("no-cached-user");
    expect(result).toBeNull();
  });

  it("normalizes invalid cached vault IDs (empty string) to null", async () => {
    await svc.saveOfflineSnapshot({
      userId: USER_ID,
      vaultId: "",
      items: [],
      categories: [],
      lastSyncedAt: null,
      updatedAt: "2026-01-01T00:00:00.000Z",
    });

    Object.defineProperty(navigator, "onLine", { value: false, configurable: true });
    const result = await svc.resolveDefaultVaultId(USER_ID);
    expect(result).toBeNull();
  });
});

// ============================================================================
// fetchRemoteOfflineSnapshot
// ============================================================================

describe("fetchRemoteOfflineSnapshot", () => {
  it("fetches vault + categories + items and saves snapshot", async () => {
    const vaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const catChain = createChainable({ data: [makeCategoryRow()], error: null });
    const itemChain = createChainable({ data: [makeItemRow()], error: null });

    mockSupabase._setChains([vaultChain, catChain, itemChain]);

    const snapshot = await svc.fetchRemoteOfflineSnapshot(USER_ID);

    expect(snapshot.userId).toBe(USER_ID);
    expect(snapshot.vaultId).toBe(VAULT_ID);
    expect(snapshot.categories).toHaveLength(1);
    expect(snapshot.items).toHaveLength(1);
    expect(snapshot.lastSyncedAt).toBeTruthy();

    // Should be persisted in IndexedDB
    const cached = await svc.getOfflineSnapshot(USER_ID);
    expect(cached).toEqual(snapshot);
  });

  it("preserves cached master-password credentials when refreshing the remote snapshot", async () => {
    await svc.saveOfflineCredentials(USER_ID, "salt-abc", "verifier-xyz", 2, "encrypted-user-key");
    await svc.saveOfflineVaultTwoFactorRequirement(USER_ID, false);

    const vaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const catChain = createChainable({ data: [makeCategoryRow()], error: null });
    const itemChain = createChainable({ data: [makeItemRow()], error: null });

    mockSupabase._setChains([vaultChain, catChain, itemChain]);

    const snapshot = await svc.fetchRemoteOfflineSnapshot(USER_ID);
    const cached = await svc.getOfflineSnapshot(USER_ID);

    expect(snapshot.encryptionSalt).toBe("salt-abc");
    expect(snapshot.masterPasswordVerifier).toBe("verifier-xyz");
    expect(snapshot.kdfVersion).toBe(2);
    expect(snapshot.encryptedUserKey).toBe("encrypted-user-key");
    expect(snapshot.vaultTwoFactorRequired).toBe(false);
    expect(cached?.encryptionSalt).toBe("salt-abc");
    expect(cached?.masterPasswordVerifier).toBe("verifier-xyz");
    expect(cached?.vaultTwoFactorRequired).toBe(false);
  });

  it("throws on DB error from categories query", async () => {
    const vaultChain = createChainable({ data: null, error: null });
    const catChain = createChainable({
      data: null,
      error: { message: "permission denied", code: "42501" },
    });

    mockSupabase._setChains([vaultChain, catChain]);

    await expect(svc.fetchRemoteOfflineSnapshot(USER_ID)).rejects.toEqual(
      expect.objectContaining({ message: "permission denied" }),
    );
  });
});

// ============================================================================
// loadVaultSnapshot
// ============================================================================

describe("loadVaultSnapshot", () => {
  it("online: returns source 'remote' after successful fetch", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    const vaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const catChain = createChainable({ data: [], error: null });
    const itemChain = createChainable({ data: [], error: null });
    mockSupabase._setChains([vaultChain, catChain, itemChain]);

    const { snapshot, source } = await svc.loadVaultSnapshot(USER_ID);

    expect(source).toBe("remote");
    expect(snapshot.userId).toBe(USER_ID);
  });

  it("tauri dev user: stays local and does not fetch remote data", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    const { snapshot, source } = await svc.loadVaultSnapshot(TAURI_DEV_USER_ID);

    expect(source).toBe("empty");
    expect(snapshot.userId).toBe(TAURI_DEV_USER_ID);
    expect(snapshot.vaultId).toBe(TAURI_DEV_VAULT_ID);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it("online: overlays a fresh local category mutation onto a stale remote snapshot", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    await svc.upsertOfflineCategoryRow(
      USER_ID,
      makeCategoryRow({ name: "enc:cat:v1:local-write" }) as CategoryRow,
    );

    const vaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const catChain = createChainable({
      data: [makeCategoryRow({ id: "cat-existing", name: "enc:cat:v1:existing" })],
      error: null,
    });
    const itemChain = createChainable({ data: [makeItemRow()], error: null });
    mockSupabase._setChains([vaultChain, catChain, itemChain]);

    const { snapshot, source } = await svc.loadVaultSnapshot(USER_ID);

    expect(source).toBe("cache");
    expect(snapshot.items).toHaveLength(1);
    expect(snapshot.categories.map((category) => category.id).sort()).toEqual(["cat-1", "cat-existing"]);
    expect(snapshot.categories.find((category) => category.id === "cat-1")?.name).toBe("enc:cat:v1:local-write");
  });

  it("online: overlays a fresh local category delete onto a stale remote snapshot", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    await svc.upsertOfflineCategoryRow(USER_ID, makeCategoryRow() as CategoryRow);
    await svc.removeOfflineCategoryRow(USER_ID, "cat-1");

    const vaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const catChain = createChainable({
      data: [makeCategoryRow(), makeCategoryRow({ id: "cat-existing" })],
      error: null,
    });
    const itemChain = createChainable({ data: [], error: null });
    mockSupabase._setChains([vaultChain, catChain, itemChain]);

    const { snapshot, source } = await svc.loadVaultSnapshot(USER_ID);

    expect(source).toBe("cache");
    expect(snapshot.categories.map((category) => category.id)).toEqual(["cat-existing"]);
  });

  it("online: keeps cached snapshot authoritative while offline mutations are pending", async () => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });

    await svc.upsertOfflineCategoryRow(USER_ID, makeCategoryRow() as CategoryRow);
    await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_category",
      payload: {
        id: "cat-1",
        user_id: USER_ID,
        name: "enc:cat:v1:name",
        icon: null,
        color: null,
      },
    });

    const { snapshot, source } = await svc.loadVaultSnapshot(USER_ID);

    expect(source).toBe("cache");
    expect(snapshot.categories.map((category) => category.id)).toEqual(["cat-1"]);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it("offline with cache: returns source 'cache'", async () => {
    // Pre-seed cache
    const cached = {
      userId: USER_ID,
      vaultId: VAULT_ID,
      items: [makeItemRow()],
      categories: [],
      lastSyncedAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    await svc.saveOfflineSnapshot(cached);

    Object.defineProperty(navigator, "onLine", { value: false, configurable: true });

    const { snapshot, source } = await svc.loadVaultSnapshot(USER_ID);

    expect(source).toBe("cache");
    expect(snapshot).toEqual(cached);
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });
});

// ============================================================================
// syncOfflineMutations
// ============================================================================

describe("syncOfflineMutations", () => {
  beforeEach(() => {
    Object.defineProperty(navigator, "onLine", { value: true, configurable: true });
  });

  it("tauri dev user: skips remote sync entirely", async () => {
    const result = await svc.syncOfflineMutations(TAURI_DEV_USER_ID);

    expect(result).toEqual({ processed: 0, remaining: 0, errors: 0 });
    expect(mockSupabase.from).not.toHaveBeenCalled();
  });

  it("replays upsert_item and delete_item mutations to Supabase", async () => {
    // Enqueue two mutations
    await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_item",
      payload: {
        id: "item-1",
        user_id: USER_ID,
        vault_id: VAULT_ID,
        title: "Sync me",
        encrypted_data: "enc-data",
      },
    } as MutationInput);

    await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "delete_item",
      payload: { id: "item-2" },
    } as MutationInput);

    // Mock Supabase calls for:
    // 1) upsert vault_items (upsert_item)
    // 2) delete vault_items (delete_item)
    // 3) fetchRemoteOfflineSnapshot calls (vaults, categories, vault_items)
    const upsertChain = createChainable({ data: null, error: null });
    const deleteChain = createChainable({ data: null, error: null });
    const refreshVaultChain = createChainable({ data: { id: VAULT_ID }, error: null });
    const refreshCatChain = createChainable({ data: [], error: null });
    const refreshItemChain = createChainable({ data: [], error: null });

    mockSupabase._setChains([
      upsertChain,     // upsert_item
      deleteChain,     // delete_item
      refreshVaultChain, // fetchRemoteOfflineSnapshot → vaults
      refreshCatChain,   // fetchRemoteOfflineSnapshot → categories
      refreshItemChain,  // fetchRemoteOfflineSnapshot → vault_items
    ]);

    const result = await svc.syncOfflineMutations(USER_ID);

    expect(result.processed).toBe(2);
    expect(result.errors).toBe(0);
    expect(result.remaining).toBe(0);
  });

  it("removes successful mutations from queue after sync", async () => {
    await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_category",
      payload: { id: "cat-1", user_id: USER_ID, name: "Work" },
    } as MutationInput);

    // upsert_category + fetchRemoteOfflineSnapshot chains
    const upsertCatChain = createChainable({ data: null, error: null });
    const refreshVaultChain = createChainable({ data: null, error: null });
    const refreshCatChain = createChainable({ data: [], error: null });

    mockSupabase._setChains([upsertCatChain, refreshVaultChain, refreshCatChain]);

    await svc.syncOfflineMutations(USER_ID);

    const remaining = await svc.getOfflineMutations(USER_ID);
    expect(remaining).toHaveLength(0);
  });

  it("returns error count when a mutation fails with non-offline error", async () => {
    await svc.enqueueOfflineMutation({
      userId: USER_ID,
      type: "upsert_item",
      payload: {
        id: "item-1",
        user_id: USER_ID,
        vault_id: VAULT_ID,
        title: "Will fail",
        encrypted_data: "enc",
      },
    } as MutationInput);

    // The upsert returns a non-network error
    const failChain = createChainable({
      data: null,
      error: { message: "constraint violation", code: "23505" },
    });

    mockSupabase._setChains([failChain]);

    const result = await svc.syncOfflineMutations(USER_ID);

    expect(result.errors).toBe(1);
    expect(result.processed).toBe(0);
    // Mutation remains in queue (not removed on non-offline error)
    expect(result.remaining).toBe(1);
  });
});
