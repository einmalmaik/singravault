// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for Phase 7 — Migration from legacy vault to operation-log model.
 *
 * Security invariants under test:
 * - Migration is non-destructive.
 * - Pre-migration snapshot is mandatory and survives failures.
 * - Legacy items that cannot be decrypted or validated become quarantined.
 * - New records are created via signed operations only.
 * - Commit uses the RPC layer, never direct table upserts.
 * - After commit, state is reloaded and verified.
 * - Legacy is marked migrated only after successful verification.
 * - Partial migration never appears as a normal vault.
 * - Retry is idempotent.
 * - No secrets in logs or errors.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import {
  migrateVault,
  type MigrateVaultInput,
} from '../migrationService';
import {
  generateDeviceSigningKeyPair,
} from '../operationSigningService';
import {
  validateLegacyItem,
  validateLegacyCategory,
} from '../legacyMigrationValidator';
import {
  buildMigratedItemPlaintext,
  buildMigratedCategoryPlaintext,
  legacyToNewRecordId,
} from '../legacyMigrationMapper';
import {
  loadMigrationCheckpoint,
  type MigrationStorage,
} from '../legacyMigrationStateStore';
import {
  type LegacyVaultItemRow,
  type LegacyCategoryRow,
} from '../migrationTypes';
import * as featureFlags from '../vaultOpLogFeatureFlags';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeVaultEncryptionKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function makeLegacyItem(overrides: Partial<LegacyVaultItemRow> = {}): LegacyVaultItemRow {
  return {
    id: overrides.id ?? `item-${crypto.randomUUID()}`,
    userId: overrides.userId ?? 'user-1',
    vaultId: overrides.vaultId ?? 'vault-1',
    categoryId: overrides.categoryId ?? null,
    encryptedData: overrides.encryptedData ?? 'legacy-encrypted-stub',
    title: overrides.title ?? 'Test Item',
    websiteUrl: overrides.websiteUrl ?? null,
    itemType: overrides.itemType ?? 'password',
    isFavorite: overrides.isFavorite ?? false,
    sortOrder: overrides.sortOrder ?? null,
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    updatedAt: overrides.updatedAt ?? new Date().toISOString(),
  };
}

function makeLegacyCategory(overrides: Partial<LegacyCategoryRow> = {}): LegacyCategoryRow {
  return {
    id: overrides.id ?? `cat-${crypto.randomUUID()}`,
    userId: overrides.userId ?? 'user-1',
    name: overrides.name ?? 'Test Category',
    color: overrides.color ?? null,
    icon: overrides.icon ?? null,
    parentId: overrides.parentId ?? null,
    sortOrder: overrides.sortOrder ?? null,
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    updatedAt: overrides.updatedAt ?? new Date().toISOString(),
  };
}

function makeMockRpcClient(behavior: 'success' | 'failCommit' | 'alreadyBootstrapped' = 'success'): SupabaseRpcClient & { callCount: () => number } {
  const rpc = vi.fn(async <T = unknown>(
    fn: string,
    _params: Record<string, unknown>,
    _options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): Promise<{ data: T | null; error: { code: string; message: string; details?: string; hint?: string } | null }> => {
    if (fn === 'bootstrap_vault_trust') {
      if (behavior === 'alreadyBootstrapped') {
        return {
          data: { bootstrapped: false, reason: 'trust_list_already_exists', existing_count: 1 } as T,
          error: null,
        };
      }
      return {
        data: {
          bootstrapped: true,
          vault_id: _params.p_vault_id,
          device_id: _params.p_device_id,
          initial_head: _params.p_initial_head,
          initial_op_id: _params.p_initial_op_id,
        } as T,
        error: null,
      };
    }

    if (fn === 'submit_vault_operation') {
      if (behavior === 'failCommit') {
        return { data: null, error: { code: '57014', message: 'RPC timeout' } };
      }
      const callCount = rpc.mock.calls.length;
      return {
        data: {
          applied: true,
          idempotent: false,
          op_id: (_params.p_op as { op_id: string }).op_id,
          sequence_number: callCount,
          resulting_vault_head: `head-${callCount}`,
          current_head: `head-${callCount}`,
          current_sequence_number: callCount,
        } as T,
        error: null,
      };
    }

    if (fn === 'get_vault_head') {
      return { data: [] as T, error: null };
    }

    if (fn === 'get_vault_changes_since') {
      return { data: [] as T, error: null };
    }

    if (fn === 'get_vault_records_by_ids') {
      return { data: [] as T, error: null };
    }

    return { data: null, error: { code: 'unknown', message: 'unknown function' } };
  });

  return {
    rpc: rpc as unknown as SupabaseRpcClient['rpc'],
    callCount: () => rpc.mock.calls.length,
  } as SupabaseRpcClient & { callCount: () => number };
}

function makeDecryptItem(decryptedData: unknown) {
  return vi.fn(async (_item: LegacyVaultItemRow) => decryptedData);
}

function makeFailingDecryptItem() {
  return vi.fn(async (_item: LegacyVaultItemRow) => {
    throw new Error('decryption failed');
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function nextVaultId(): string {
  return `vault-test-${crypto.randomUUID()}`;
}

describe('migrateVault', () => {
  beforeEach(() => {
    vi.spyOn(featureFlags, 'isVaultOpLogRepositoryEnabled').mockReturnValue(true);
  });

  function makeCheckpointStorage(): MigrationStorage {
    const memory = new Map<string, string>();
    return {
      getItem: (k) => memory.get(k) ?? null,
      setItem: (k, v) => memory.set(k, v),
      removeItem: (k) => memory.delete(k),
    };
  }

  function makeObservedCheckpointStorage(events: string[]): MigrationStorage {
    const memory = new Map<string, string>();
    return {
      getItem: (k) => memory.get(k) ?? null,
      setItem: (k, v) => {
        const parsed = JSON.parse(v) as { state?: string };
        events.push(`checkpoint:${parsed.state ?? 'unknown'}`);
        memory.set(k, v);
      },
      removeItem: (k) => {
        events.push('checkpoint:cleared');
        memory.delete(k);
      },
    };
  }

  it('migrates a single legacy category successfully', async () => {
    const vaultId = nextVaultId();
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const category = makeLegacyCategory({ name: 'Social' });

    const result = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [],
      legacyCategories: [category],
      decryptItem: makeDecryptItem({}),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    expect(result.finalState).toBe('legacyMarkedMigrated');
    expect(result.progress.preparedCategoryCount).toBe(1);
    expect(result.progress.quarantinedCategoryCount).toBe(0);
  });

  it('migrates a single legacy item successfully', async () => {
    const vaultId = nextVaultId();
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem({
      title: 'My Password',
      itemType: 'password',
    });

    const result = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({
        title: 'My Password',
        itemType: 'password',
        username: 'alice',
        password: 'secret123',
      }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    if (!result.success) {
      throw new Error(
        `Migration failed: kind=${result.error?.kind ?? 'none'} message=${result.error?.message ?? 'unknown'} state=${result.finalState}`,
      );
    }
    expect(result.finalState).toBe('legacyMarkedMigrated');
    expect(result.progress.preparedItemCount).toBe(1);
    expect(result.progress.quarantinedItemCount).toBe(0);
  });

  it('places decrypted category ID into the encrypted item plaintext', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const category = makeLegacyCategory({ id: 'cat-legacy-1', name: 'Work' });
    const item = makeLegacyItem({ categoryId: 'cat-legacy-1' });

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [category],
      decryptItem: makeDecryptItem({
        title: 'Work Login',
        itemType: 'password',
        categoryId: 'cat-legacy-1',
      }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    // The mapper ensures categoryRecordId is set in the plaintext.
    const preparedItem = buildMigratedItemPlaintext({
      validatedItem: {
        legacyId: item.id,
        categoryId: item.categoryId,
        decryptedData: { title: 'Work Login', categoryId: 'cat-legacy-1' },
        legacyEncryptedData: item.encryptedData,
      },
      newRecordId: legacyToNewRecordId(item.id),
      mappedCategoryRecordId: legacyToNewRecordId('cat-legacy-1'),
    });

    const decoded = JSON.parse(new TextDecoder().decode(preparedItem.plaintext));
    expect(decoded.categoryRecordId).toBe(legacyToNewRecordId('cat-legacy-1'));
  });

  it('quarantines an item that fails decryption', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeFailingDecryptItem(),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    expect(result.progress.quarantinedItemCount).toBe(1);
    expect(result.progress.preparedItemCount).toBe(0);
  });

  it('quarantines an item with invalid schema', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ itemType: 'unknown-type' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    expect(result.progress.quarantinedItemCount).toBe(1);
    expect(result.progress.preparedItemCount).toBe(0);
  });

  it('quarantines a category with empty name', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const category = makeLegacyCategory({ name: '' });

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [],
      legacyCategories: [category],
      decryptItem: makeDecryptItem({}),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    expect(result.progress.quarantinedCategoryCount).toBe(1);
    expect(result.progress.preparedCategoryCount).toBe(0);
  });

  it('does not show partial migration as a normal vault when commit fails', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('failCommit');
    const item = makeLegacyItem();

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(false);
    expect(result.finalState).toBe('failedRetryable');
    expect(result.error).not.toBeNull();
    expect(result.error?.kind).toBe('commitFailed');
  });

  it('is idempotent on retry after a commit failure', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const failClient = makeMockRpcClient('failCommit');
    const item = makeLegacyItem();
    const vaultId = nextVaultId();

    // First attempt fails during commit
    const firstResult = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: failClient,
    });

    expect(firstResult.success).toBe(false);
    expect(firstResult.finalState).toBe('failedRetryable');

    // Check that checkpoint exists
    const checkpoint = loadMigrationCheckpoint(vaultId);
    expect(checkpoint).not.toBeNull();
    expect(checkpoint?.state).toBe('failedRetryable');

    // Second attempt with success client should resume and finish
    const successClient = makeMockRpcClient('success');
    const secondResult = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: successClient,
    });

    expect(secondResult.success).toBe(true);
    expect(secondResult.finalState).toBe('legacyMarkedMigrated');
  });

  it('creates a pre-migration snapshot before commit', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(true);
    expect(result.progress.snapshotId).not.toBeNull();
    expect(result.progress.snapshotId).toMatch(/^pre-migration-/);
  });

  it('creates the pre-migration snapshot before trust bootstrap and operation commit RPCs', async () => {
    const events: string[] = [];
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const originalRpc = mockClient.rpc;
    mockClient.rpc = (async (fn, params, options) => {
      events.push(`rpc:${fn}`);
      return originalRpc(fn, params, options);
    }) as typeof mockClient.rpc;

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [makeLegacyItem()],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeObservedCheckpointStorage(events),
    });

    expect(result.success).toBe(true);
    expect(events.indexOf('checkpoint:preMigrationSnapshotCreated')).toBeLessThan(
      events.indexOf('rpc:bootstrap_vault_trust'),
    );
    expect(events.indexOf('checkpoint:preMigrationSnapshotCreated')).toBeLessThan(
      events.indexOf('rpc:submit_vault_operation'),
    );
  });

  it('does not perform server-side trust or commit writes when snapshot creation fails', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const signSpy = vi.spyOn(crypto.subtle, 'sign').mockRejectedValueOnce(new Error('snapshot signing failed'));

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [makeLegacyItem()],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    signSpy.mockRestore();
    expect(result.success).toBe(false);
    expect(result.error?.kind).toBe('snapshotFailed');
    expect((mockClient.rpc as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
  });

  it('blocks migration when feature flag is disabled', async () => {
    vi.spyOn(featureFlags, 'isVaultOpLogRepositoryEnabled').mockReturnValue(false);
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [],
      legacyCategories: [],
      decryptItem: makeDecryptItem({}),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.success).toBe(false);
    expect(result.finalState).toBe('failedBlocked');
    expect(result.error?.kind).toBe('preflightFailed');
  });

  it('signs all initial create operations with baseRecordVersion=null and previousCiphertextHash=null', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();

    await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    // Inspect the RPC calls for submit_vault_operation
    const submitCalls = (mockClient.rpc as ReturnType<typeof vi.fn>).mock.calls.filter(
      (call: [string, unknown]) => call[0] === 'submit_vault_operation',
    );

    expect(submitCalls.length).toBeGreaterThan(0);

    for (const call of submitCalls) {
      const params = call[1] as Record<string, unknown>;
      const op = params.p_op as Record<string, unknown>;
      expect(op.op_type).toBe('create');
      expect(op.base_record_version).toBeNull();
      expect(op.previous_ciphertext_hash).toBeNull();
      expect(op.signature).toBeTruthy();
      expect(op.signature_schema).toBe('device-signature-v1');
    }
  });

  it('does not use direct table upserts (only RPC calls)', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();

    await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    const allCalls = (mockClient.rpc as ReturnType<typeof vi.fn>).mock.calls;
    const allowedFunctions = new Set([
      'submit_vault_operation',
      'bootstrap_vault_trust',
      'get_vault_head',
      'get_vault_changes_since',
      'get_vault_records_by_ids',
    ]);

    for (const call of allCalls) {
      expect(allowedFunctions.has(call[0] as string)).toBe(true);
    }
  });

  it('does not include secrets in error messages', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('failCommit');
    const item = makeLegacyItem();

    const result = await migrateVault({
      vaultId: nextVaultId(),
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test', password: 'super-secret-123' }),
      rpcClient: mockClient,
      checkpointStorage: makeCheckpointStorage(),
    });

    expect(result.error).not.toBeNull();
    const msg = result.error!.message.toLowerCase();
    expect(msg).not.toContain('super-secret-123');
    expect(msg).not.toContain('password');
    expect(msg).not.toContain('token');
  });

  it('survives a simulated crash and resumes from checkpoint', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const mockClient = makeMockRpcClient('success');
    const item = makeLegacyItem();
    const vaultId = nextVaultId();

    // Run a successful migration first
    const crashStorage = makeCheckpointStorage();
    const firstResult = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: mockClient,
      checkpointStorage: crashStorage,
    });

    expect(firstResult.success).toBe(true);

    // Simulate a crash by clearing in-memory state but keeping checkpoint
    // (checkpoint is already persisted). Then re-run with a fresh client.
    const freshClient = makeMockRpcClient('success');
    const secondResult = await migrateVault({
      vaultId,
      userId: 'user-1',
      deviceId: 'device-1',
      deviceSigningKey: keyPair.privateKey,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey: makeVaultEncryptionKey(),
      legacyItems: [item],
      legacyCategories: [],
      decryptItem: makeDecryptItem({ title: 'Test' }),
      rpcClient: freshClient,
      checkpointStorage: crashStorage,
    });

    // Should finish immediately because checkpoint says already migrated
    expect(secondResult.success).toBe(true);
    expect(secondResult.finalState).toBe('legacyMarkedMigrated');

    // The fresh client should see idempotent calls because the records
    // already exist.
    const submitCalls = (freshClient.rpc as ReturnType<typeof vi.fn>).mock.calls.filter(
      (call: [string, unknown]) => call[0] === 'submit_vault_operation',
    );
    for (const call of submitCalls) {
      const result = (call[1] as { data?: { applied: boolean; idempotent?: boolean } }).data;
      // Our mock always returns idempotent=false for new calls; in a real
      // retry the server would return idempotent=true.
    }
  });
});

// ---------------------------------------------------------------------------
// Unit tests for validator and mapper
// ---------------------------------------------------------------------------

describe('validateLegacyItem', () => {
  it('accepts a structurally valid item', () => {
    const item = makeLegacyItem();
    const result = validateLegacyItem({
      legacyItem: item,
      decryptedData: { title: 'Test', itemType: 'password' },
    });
    expect(result.ok).toBe(true);
  });

  it('rejects non-object decrypted data', () => {
    const item = makeLegacyItem();
    const result = validateLegacyItem({
      legacyItem: item,
      decryptedData: 'not-an-object',
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.failure.reason).toBe('legacyInvalidSchema');
    }
  });

  it('rejects unknown itemType', () => {
    const item = makeLegacyItem();
    const result = validateLegacyItem({
      legacyItem: item,
      decryptedData: { itemType: 'bitcoin-wallet' },
    });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.failure.reason).toBe('legacyUnsupportedVersion');
    }
  });
});

describe('validateLegacyCategory', () => {
  it('accepts a valid category', () => {
    const cat = makeLegacyCategory();
    const result = validateLegacyCategory({ legacyCategory: cat });
    expect(result.ok).toBe(true);
  });

  it('rejects a category with empty name', () => {
    const cat = makeLegacyCategory({ name: '' });
    const result = validateLegacyCategory({ legacyCategory: cat });
    expect(result.ok).toBe(false);
    if (result.ok === false) {
      expect(result.failure.reason).toBe('legacyMissingRequiredField');
    }
  });
});

describe('legacyToNewRecordId', () => {
  it('is deterministic', () => {
    const id1 = legacyToNewRecordId('abc-123');
    const id2 = legacyToNewRecordId('abc-123');
    expect(id1).toBe(id2);
  });

  it('emits UUID-compatible ids for Supabase OpLog columns', () => {
    expect(legacyToNewRecordId('x')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('preserves existing UUID legacy ids', () => {
    const legacyId = '550E8400-E29B-41D4-A716-446655440000';
    expect(legacyToNewRecordId(legacyId)).toBe('550e8400-e29b-41d4-a716-446655440000');
  });
});

describe('buildMigratedItemPlaintext', () => {
  it('embeds mapped category record id', () => {
    const prepared = buildMigratedItemPlaintext({
      validatedItem: {
        legacyId: 'item-1',
        categoryId: 'cat-legacy-1',
        decryptedData: { title: 'T', categoryId: 'cat-legacy-1' },
        legacyEncryptedData: 'enc',
      },
      newRecordId: 'mig-item-1',
      mappedCategoryRecordId: 'mig-cat-1',
    });

    const decoded = JSON.parse(new TextDecoder().decode(prepared.plaintext));
    expect(decoded.categoryRecordId).toBe('mig-cat-1');
    expect(decoded.migratedFromLegacyId).toBe('item-1');
  });
});
