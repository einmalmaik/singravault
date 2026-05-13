// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  evaluateVaultMigrationGate,
} from '../vaultMigrationRolloutService';
import { saveVerifiedVaultOpLogOfflineCache } from '../vaultOpLogOfflineStore';
import {
  loadMigrationCompletionMarker,
  saveMigrationCheckpoint,
  saveMigrationCompletionMarker,
  type MigrationStorage,
} from '../legacyMigrationStateStore';
import { DEVICE_SIGNATURE_SCHEMA_V1, type TrustedDeviceRecordV1 } from '../types';
import type { MigrationState } from '../migrationTypes';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import type { VaultOperationRow, VaultRecordRow } from '../vaultOpLogRpcTypes';

let restoreNavigatorOnline: (() => void) | null = null;

afterEach(() => {
  restoreNavigatorOnline?.();
  restoreNavigatorOnline = null;
});

function makeStorage(): MigrationStorage {
  const data = new Map<string, string>();
  return {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    removeItem: (key) => data.delete(key),
  };
}

function saveCheckpoint(storage: MigrationStorage, vaultId: string, state: MigrationState): void {
  saveMigrationCheckpoint({
    version: 1,
    vaultId,
    state,
    snapshotId: null,
    legacyToNewRecordIdMap: {},
    quarantinedLegacyIds: [],
    committedOpIds: [],
    error: null,
    updatedAt: '2026-05-05T00:00:00.000Z',
  }, storage);
}

function makeClient(input: {
  vaultId?: string | null;
  itemCount?: number;
  categoryCount?: number;
}) {
  return {
    from(table: string) {
      return {
        select() {
          return this;
        },
        eq() {
          if (table === 'vault_items') {
            return Promise.resolve({ count: input.itemCount ?? 0, error: null });
          }
          if (table === 'categories') {
            return Promise.resolve({ count: input.categoryCount ?? 0, error: null });
          }
          return this;
        },
        maybeSingle() {
          return Promise.resolve({
            data: input.vaultId === undefined ? { id: 'vault-1' } : input.vaultId ? { id: input.vaultId } : null,
            error: null,
          });
        },
      };
    },
  } as never;
}

function makeRpc(hasHead = false): SupabaseRpcClient {
  return {
    rpc: async () => ({
      data: hasHead
        ? [{
          vault_id: 'vault-1',
          current_head: 'head-1',
          current_op_id: 'op-1',
          current_sequence_number: 1,
          updated_at: '2026-05-05T00:00:00.000Z',
        }]
        : [],
      error: null,
    }),
  };
}

function makeFreshOpLogRpc(): SupabaseRpcClient {
  return {
    rpc: async (fn: string) => {
      if (fn === 'get_vault_head') {
        return {
          data: [{
            vault_id: 'vault-1',
            current_head: 'head-1',
            current_op_id: null,
            current_sequence_number: 0,
            updated_at: '2026-05-05T00:00:00.000Z',
          }],
          error: null,
        };
      }
      if (fn === 'get_vault_changes_since') {
        return { data: [], error: null };
      }
      return { data: null, error: { code: 'TEST', message: `unexpected rpc ${fn}` } };
    },
  };
}

function makeTrustClient() {
  return {
    from() {
      return {
        select() {
          return {
            eq() {
              return Promise.resolve({
                data: [{
                  vault_id: 'vault-1',
                  device_id: 'device-1',
                  public_signing_key: 'pub-local',
                  device_name_encrypted: '',
                  added_by_device_id: null,
                  added_op_id: null,
                  added_at: '2026-05-05T00:00:00.000Z',
                  trust_epoch: 0,
                  status: 'trusted',
                  revoked_at: null,
                  revoked_by_device_id: null,
                }],
                error: null,
              });
            },
          };
        },
      };
    },
  } as never;
}

describe('evaluateVaultMigrationGate', () => {
  it('allows normal unlock when no legacy rows and no checkpoint exist', async () => {
    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1' }),
      rpcClient: makeRpc(false),
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'notNeeded',
    });
  });

  it('treats a fresh bootstrapped OpLog vault as verified after working-set verification', async () => {
    const vaultEncryptionKey = new Uint8Array(32).fill(7);

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1' }),
      rpcClient: makeFreshOpLogRpc(),
      trustClient: makeTrustClient(),
      vaultEncryptionKey,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
      vaultId: 'vault-1',
      reason: null,
    });
  });

  it('blocks normal unlock when legacy rows require migration', async () => {
    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1', itemCount: 1 }),
      rpcClient: makeRpc(false),
    });

    expect(result).toMatchObject({
      allowNormalUnlock: false,
      status: 'required',
    });
  });

  it.each([
    ['preflightChecked', 'ready'],
    ['deviceTrustPrepared', 'running'],
    ['commitCompleted', 'committed'],
    ['failedRetryable', 'failed'],
  ] as const)('blocks normal unlock for checkpoint %s as %s', async (checkpointState, status) => {
    const storage = makeStorage();
    saveCheckpoint(storage, 'vault-1', checkpointState);

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1' }),
      rpcClient: makeRpc(false),
      checkpointStorage: storage,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: false,
      status,
    });
  });

  it('allows normal unlock for verified checkpoints', async () => {
    const storage = makeStorage();
    saveCheckpoint(storage, 'vault-1', 'verified');

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1' }),
      rpcClient: makeRpc(false),
      checkpointStorage: storage,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
    });
  });

  it('allows normal unlock after verified completion even when legacy rows remain', async () => {
    const storage = makeStorage();
    saveMigrationCompletionMarker({
      version: 1,
      vaultId: 'vault-1',
      state: 'verified',
      completedAt: '2026-05-05T00:00:00.000Z',
    }, storage);

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1', itemCount: 1, categoryCount: 1 }),
      rpcClient: makeRpc(true),
      checkpointStorage: storage,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
    });
  });

  it('allows cross-platform unlock when legacy rows remain but remote OpLog verifies', async () => {
    const storage = makeStorage();
    const vaultEncryptionKey = new Uint8Array(32).fill(3);
    const remoteOpLogVerifier = vi.fn(async () => ({ verified: true, error: null }));

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1', itemCount: 1, categoryCount: 1 }),
      rpcClient: makeRpc(true),
      checkpointStorage: storage,
      vaultEncryptionKey,
      remoteOpLogVerifier,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
      vaultId: 'vault-1',
      reason: null,
    });
    expect(remoteOpLogVerifier).toHaveBeenCalledWith(expect.objectContaining({
      vaultId: 'vault-1',
      vaultEncryptionKey,
    }));
    expect(loadMigrationCompletionMarker('vault-1', storage)).toBeNull();
  });

  it('does not allow legacy rows plus remote OpLog head by head existence alone', async () => {
    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1', itemCount: 1 }),
      rpcClient: makeRpc(true),
    });

    expect(result).toMatchObject({
      allowNormalUnlock: false,
      status: 'preflightFailed',
      vaultId: 'vault-1',
    });
  });

  it('blocks cross-platform unlock when remote OpLog verification fails', async () => {
    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      client: makeClient({ vaultId: 'vault-1', itemCount: 1 }),
      rpcClient: makeRpc(true),
      vaultEncryptionKey: new Uint8Array(32).fill(4),
      remoteOpLogVerifier: vi.fn(async () => ({ verified: false, error: 'vault_head_mismatch' })),
    });

    expect(result).toMatchObject({
      allowNormalUnlock: false,
      status: 'preflightFailed',
      vaultId: 'vault-1',
      reason: 'vault_head_mismatch',
    });
  });

  it('allows offline unlock for migrated vaults only after the local OpLog cache verifies', async () => {
    restoreNavigatorOnline = setNavigatorOnline(false);
    const vaultEncryptionKey = new Uint8Array(32).fill(5);
    const offlineOpLogVerifier = vi.fn(async () => ({ verified: true, error: null }));

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      vaultEncryptionKey,
      offlineVaultIdResolver: async () => 'vault-1',
      offlineOpLogVerifier,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
      vaultId: 'vault-1',
      reason: null,
    });
    expect(offlineOpLogVerifier).toHaveBeenCalledWith({
      userId: 'user-1',
      vaultId: 'vault-1',
      vaultEncryptionKey,
    });
  });

  it('resolves offline migrated vaults from the verified OpLog cache when legacy snapshots have no vault id', async () => {
    restoreNavigatorOnline = setNavigatorOnline(false);
    installFakeIndexedDb();
    const vaultEncryptionKey = new Uint8Array(32).fill(8);
    const offlineOpLogVerifier = vi.fn(async () => ({ verified: true, error: null }));

    await saveVerifiedVaultOpLogOfflineCache({
      userId: 'user-1',
      vaultId: 'vault-1',
      currentHead: 'head-1',
      currentSequenceNumber: 1,
      operations: [operationRow('vault-1')],
      records: [recordRow('vault-1')],
      trustedDevices: [trustedDevice('vault-1')],
    });

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      vaultEncryptionKey,
      offlineOpLogVerifier,
    });

    expect(result).toMatchObject({
      allowNormalUnlock: true,
      status: 'verified',
      vaultId: 'vault-1',
      reason: null,
    });
    expect(offlineOpLogVerifier).toHaveBeenCalledWith({
      userId: 'user-1',
      vaultId: 'vault-1',
      vaultEncryptionKey,
    });
  });

  it('keeps offline migrated vaults locked when no verified local OpLog cache is available', async () => {
    restoreNavigatorOnline = setNavigatorOnline(false);

    const result = await evaluateVaultMigrationGate({
      userId: 'user-1',
      vaultEncryptionKey: new Uint8Array(32).fill(6),
      offlineVaultIdResolver: async () => 'vault-1',
      offlineOpLogVerifier: vi.fn(async () => ({
        verified: false,
        error: 'offline_op_log_state_missing',
      })),
    });

    expect(result).toMatchObject({
      allowNormalUnlock: false,
      status: 'preflightFailed',
      vaultId: 'vault-1',
      reason: 'offline_op_log_state_missing',
    });
  });
});

describe('legacy vault runtime write contract', () => {
  it('does not keep direct legacy vault table writes in runtime source', () => {
    const runtimeFiles = listSourceFiles(join(process.cwd(), 'src'))
      .filter((file) => !file.includes(`${join('src', 'services', 'vaultOpLog', '__tests__')}`))
      .filter((file) => !file.includes(`${join('src', 'test')}`));
    const fromVaultItems = String.raw`\.from\((?:['"])vault_items(?:['"])\)`;
    const fromCategories = String.raw`\.from\((?:['"])categories(?:['"])\)`;
    const writeMethod = String.raw`\.(insert|update|upsert|delete)\s*\(`;
    const forbidden = new RegExp(`(?:${fromVaultItems}|${fromCategories})[\\s\\S]{0,240}${writeMethod}`, 'm');

    const offenders = runtimeFiles
      .filter((file) => forbidden.test(readFileSync(file, 'utf8')))
      .map((file) => relative(process.cwd(), file).replace(/\\/g, '/'));

    expect(offenders).toEqual([]);
  });
});

function listSourceFiles(root: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      files.push(...listSourceFiles(path));
      continue;
    }
    if (/\.(ts|tsx)$/.test(path)) {
      files.push(path);
    }
  }
  return files;
}

function setNavigatorOnline(online: boolean): () => void {
  const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'onLine')
    ?? Object.getOwnPropertyDescriptor(navigator, 'onLine');
  Object.defineProperty(navigator, 'onLine', {
    configurable: true,
    get: () => online,
  });

  return () => {
    if (descriptor) {
      Object.defineProperty(navigator, 'onLine', descriptor);
    }
  };
}

interface StoreMeta {
  readonly keyPath: string;
  readonly data: Map<string, unknown>;
}

class FakeIDBObjectStore {
  constructor(private readonly meta: StoreMeta) {}

  get(key: unknown): FakeIDBRequest {
    return new FakeIDBRequest(this.meta.data.get(String(key)));
  }

  getAll(): FakeIDBRequest {
    return new FakeIDBRequest(Array.from(this.meta.data.values()));
  }

  put(value: unknown): FakeIDBRequest {
    const key = (value as Record<string, unknown>)[this.meta.keyPath];
    this.meta.data.set(String(key), value);
    return new FakeIDBRequest(key);
  }
}

class FakeIDBTransaction {
  constructor(private readonly db: FakeIDBDatabase) {}

  objectStore(name: string): FakeIDBObjectStore {
    const meta = this.db.stores.get(name);
    if (!meta) {
      throw new DOMException(`Object store "${name}" not found`, 'NotFoundError');
    }
    return new FakeIDBObjectStore(meta);
  }
}

class FakeIDBDatabase {
  readonly stores = new Map<string, StoreMeta>();

  get objectStoreNames(): { contains: (name: string) => boolean } {
    return { contains: (name: string) => this.stores.has(name) };
  }

  createObjectStore(name: string, options?: { keyPath?: string }): FakeIDBObjectStore {
    const meta = {
      keyPath: options?.keyPath ?? 'id',
      data: new Map<string, unknown>(),
    };
    this.stores.set(name, meta);
    return new FakeIDBObjectStore(meta);
  }

  transaction(): FakeIDBTransaction {
    return new FakeIDBTransaction(this);
  }
}

class FakeIDBRequest {
  result: unknown;
  error: DOMException | null = null;
  onsuccess: ((event: unknown) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  onupgradeneeded: (() => void) | null = null;

  constructor(result: unknown, private readonly triggerUpgrade = false) {
    this.result = result;
    Promise.resolve().then(() => {
      if (this.triggerUpgrade) {
        this.onupgradeneeded?.();
      }
      this.onsuccess?.({ target: this });
    });
  }
}

function installFakeIndexedDb(): void {
  const fakeDb = new FakeIDBDatabase();
  const idb = globalThis.indexedDB as unknown as Record<string, unknown>;
  idb.open = () => new FakeIDBRequest(fakeDb, true);
}

function operationRow(vaultId: string): VaultOperationRow {
  return {
    opId: 'op-1',
    opHash: 'op-hash-1',
    vaultId,
    authorDeviceId: 'device-1',
    opType: 'create',
    recordId: 'record-1',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'record-hash-1',
    baseVaultHead: null,
    resultingVaultHead: 'head-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    payloadCiphertextHash: 'ciphertext-hash-1',
    payloadAadHash: 'aad-hash-1',
    signedBody: {},
    signature: 'signature-1',
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    trustEpoch: 0,
    createdAtClient: '2026-05-12T00:00:00.000Z',
    receivedAtServer: '2026-05-12T00:00:00.000Z',
    sequenceNumber: 1,
  };
}

function recordRow(vaultId: string): VaultRecordRow {
  return {
    vaultId,
    recordId: 'record-1',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
    aadHash: 'aad-hash-1',
    ciphertextHash: 'ciphertext-hash-1',
    nonce: 'nonce-1',
    ciphertext: 'sealed-ciphertext-1',
    lastOpId: 'op-1',
    lastOpHash: 'op-hash-1',
    isTombstone: false,
    createdAt: '2026-05-12T00:00:00.000Z',
    updatedAt: '2026-05-12T00:00:00.000Z',
  };
}

function trustedDevice(vaultId: string): TrustedDeviceRecordV1 {
  return {
    vaultId,
    deviceId: 'device-1',
    publicSigningKey: 'public-key-1',
    deviceNameEncrypted: '',
    addedByDeviceId: null,
    addedAt: '2026-05-12T00:00:00.000Z',
    trustEpoch: 0,
    status: 'trusted',
    revokedAt: null,
    revokedByDeviceId: null,
  };
}
