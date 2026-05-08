// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it, vi } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  evaluateVaultMigrationGate,
} from '../vaultMigrationRolloutService';
import {
  loadMigrationCompletionMarker,
  saveMigrationCheckpoint,
  saveMigrationCompletionMarker,
  type MigrationStorage,
} from '../legacyMigrationStateStore';
import type { MigrationState } from '../migrationTypes';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';

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
