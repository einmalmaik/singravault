// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runControlledMigration } from '../vaultMigrationRuntimeOrchestrator';
import { getVaultHead } from '../vaultOpLogRepository';
import { loadVaultOpLogUiState } from '../vaultOpLogUiOrchestrator';
import { migrateVault } from '../migrationService';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';

vi.mock('../vaultOpLogRepository', async () => {
  const actual = await vi.importActual<typeof import('../vaultOpLogRepository')>('../vaultOpLogRepository');
  return {
    ...actual,
    getVaultHead: vi.fn(),
  };
});

vi.mock('../vaultOpLogUiOrchestrator', () => ({
  loadVaultOpLogUiState: vi.fn(),
}));

vi.mock('../migrationService', () => ({
  migrateVault: vi.fn(),
}));

const mockGetVaultHead = vi.mocked(getVaultHead);
const mockLoadVaultOpLogUiState = vi.mocked(loadVaultOpLogUiState);
const mockMigrateVault = vi.mocked(migrateVault);

function makeRpcClient(): SupabaseRpcClient {
  return {
    rpc: vi.fn(),
  };
}

function makeReadClient() {
  return {
    from: vi.fn(),
  } as never;
}

function makeMigrationKeyContext() {
  return {
    activeKey: {} as CryptoKey,
    vaultEncryptionKey: new Uint8Array(32).fill(7),
  };
}

describe('runControlledMigration remote migration preflight', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('adopts an already verified remote OpLog migration instead of starting a second migration', async () => {
    mockGetVaultHead.mockResolvedValue({
      kind: 'success',
      head: {
        vaultId: 'vault-1',
        currentHead: 'head-1',
        currentOpId: 'op-1',
        currentSequenceNumber: 1,
        updatedAt: '2026-05-08T00:00:00.000Z',
      },
    });
    mockLoadVaultOpLogUiState.mockResolvedValue({
      uiView: null,
      localVaultState: {
        recordsById: new Map([
          ['manifest-record', {
            recordState: 'verified',
            record: { recordType: 'manifest' },
          }],
        ]),
        quarantinedRecordsById: new Map(),
        conflictsByRecordId: new Map(),
        trustedDevicesById: new Map(),
        lastVerifiedVaultHead: 'head-1',
      } as never,
      error: null,
    });

    const result = await runControlledMigration({
      userId: 'user-1',
      vaultId: 'vault-1',
      migrationKeyContext: makeMigrationKeyContext(),
      decryptLegacyItem: vi.fn(),
      client: makeReadClient(),
      rpcClient: makeRpcClient(),
    });

    expect(result).toMatchObject({
      success: true,
      migrationResult: null,
      error: null,
    });
    expect(mockMigrateVault).not.toHaveBeenCalled();
  });

  it('fails closed when a remote OpLog head exists but no verified migration manifest can be proven', async () => {
    mockGetVaultHead.mockResolvedValue({
      kind: 'success',
      head: {
        vaultId: 'vault-1',
        currentHead: 'head-1',
        currentOpId: 'op-1',
        currentSequenceNumber: 1,
        updatedAt: '2026-05-08T00:00:00.000Z',
      },
    });
    mockLoadVaultOpLogUiState.mockResolvedValue({
      uiView: null,
      localVaultState: null,
      error: 'vault_head_mismatch',
    });

    const result = await runControlledMigration({
      userId: 'user-1',
      vaultId: 'vault-1',
      migrationKeyContext: makeMigrationKeyContext(),
      decryptLegacyItem: vi.fn(),
      client: makeReadClient(),
      rpcClient: makeRpcClient(),
    });

    expect(result.success).toBe(false);
    expect(result.error?.message).toContain('Remote-OpLog existiert bereits');
    expect(result.error?.message).toContain('vault_head_mismatch');
    expect(mockMigrateVault).not.toHaveBeenCalled();
  });
});
