import { beforeEach, describe, expect, it, vi } from 'vitest';

const supabaseState = vi.hoisted(() => ({
  rpcCalls: [] as Array<{ name: string; args?: Record<string, unknown> }>,
  rpcResults: [] as Array<{
    data: unknown;
    error: { message: string } | null;
  }>,
}));

const dependencyMocks = vi.hoisted(() => ({
  clearOfflineVaultData: vi.fn(async () => undefined),
  clearIntegrityBaseline: vi.fn(async () => undefined),
  deleteDeviceKey: vi.fn(async () => undefined),
}));

vi.mock('@/integrations/supabase/client', () => ({
  supabase: {
    rpc: async (name: string, args?: Record<string, unknown>) => {
      supabaseState.rpcCalls.push({ name, args });
      return supabaseState.rpcResults.shift() ?? { data: null, error: null };
    },
  },
}));

vi.mock('@/services/offlineVaultService', () => ({
  clearOfflineVaultData: dependencyMocks.clearOfflineVaultData,
}));

vi.mock('@/services/vaultIntegrityService', () => ({
  clearIntegrityBaseline: dependencyMocks.clearIntegrityBaseline,
}));

vi.mock('@/services/deviceKeyService', () => ({
  deleteDeviceKey: dependencyMocks.deleteDeviceKey,
}));

import {
  VaultRecoveryResetError,
  resetUserVaultState,
} from '@/services/vaultRecoveryService';

describe('vaultRecoveryService', () => {
  beforeEach(() => {
    supabaseState.rpcCalls.length = 0;
    supabaseState.rpcResults.length = 0;
    dependencyMocks.clearOfflineVaultData.mockClear();
    dependencyMocks.clearIntegrityBaseline.mockClear();
    dependencyMocks.deleteDeviceKey.mockClear();
  });

  it('starts an explicit recovery challenge before the atomic remote reset', async () => {
    supabaseState.rpcResults.push(
      {
        data: {
          challenge_id: 'challenge-1',
          expires_at: '2026-04-23T17:05:00.000Z',
        },
        error: null,
      },
      {
        data: { reset: true },
        error: null,
      },
    );

    await resetUserVaultState('user-1');

    expect(supabaseState.rpcCalls).toEqual([
      { name: 'begin_vault_reset_recovery', args: undefined },
      {
        name: 'reset_user_vault_state',
        args: { p_recovery_challenge_id: 'challenge-1' },
      },
    ]);
    expect(dependencyMocks.clearOfflineVaultData).toHaveBeenCalledWith('user-1');
    expect(dependencyMocks.clearIntegrityBaseline).toHaveBeenCalledWith('user-1');
    expect(dependencyMocks.deleteDeviceKey).toHaveBeenCalledWith('user-1');
  });

  it('rejects stale sessions when the server requires fresh reauthentication', async () => {
    supabaseState.rpcResults.push({
      data: null,
      error: { message: 'REAUTH_REQUIRED' },
    });

    await expect(resetUserVaultState('user-1')).rejects.toEqual(
      expect.objectContaining<VaultRecoveryResetError>({
        name: 'VaultRecoveryResetError',
        code: 'REAUTH_REQUIRED',
        message: 'REAUTH_REQUIRED',
      }),
    );

    expect(supabaseState.rpcCalls).toEqual([
      { name: 'begin_vault_reset_recovery', args: undefined },
    ]);
    expect(dependencyMocks.clearOfflineVaultData).not.toHaveBeenCalled();
    expect(dependencyMocks.clearIntegrityBaseline).not.toHaveBeenCalled();
    expect(dependencyMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });

  it('fails closed when the server does not return a usable recovery challenge', async () => {
    supabaseState.rpcResults.push({
      data: { expires_at: '2026-04-23T17:05:00.000Z' },
      error: null,
    });

    await expect(resetUserVaultState('user-1')).rejects.toEqual(
      expect.objectContaining<VaultRecoveryResetError>({
        name: 'VaultRecoveryResetError',
        code: 'RECOVERY_CHALLENGE_REQUIRED',
        message: 'RECOVERY_CHALLENGE_REQUIRED',
      }),
    );

    expect(supabaseState.rpcCalls).toEqual([
      { name: 'begin_vault_reset_recovery', args: undefined },
    ]);
    expect(dependencyMocks.clearOfflineVaultData).not.toHaveBeenCalled();
    expect(dependencyMocks.clearIntegrityBaseline).not.toHaveBeenCalled();
    expect(dependencyMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });

  it('surfaces a missing or expired server challenge from the destructive RPC', async () => {
    supabaseState.rpcResults.push(
      {
        data: {
          challenge_id: 'challenge-1',
          expires_at: '2026-04-23T17:05:00.000Z',
        },
        error: null,
      },
      {
        data: null,
        error: { message: 'RECOVERY_CHALLENGE_REQUIRED' },
      },
    );

    await expect(resetUserVaultState('user-1')).rejects.toEqual(
      expect.objectContaining<VaultRecoveryResetError>({
        name: 'VaultRecoveryResetError',
        code: 'RECOVERY_CHALLENGE_REQUIRED',
        message: 'RECOVERY_CHALLENGE_REQUIRED',
      }),
    );

    expect(supabaseState.rpcCalls).toEqual([
      { name: 'begin_vault_reset_recovery', args: undefined },
      {
        name: 'reset_user_vault_state',
        args: { p_recovery_challenge_id: 'challenge-1' },
      },
    ]);
    expect(dependencyMocks.clearOfflineVaultData).not.toHaveBeenCalled();
    expect(dependencyMocks.clearIntegrityBaseline).not.toHaveBeenCalled();
    expect(dependencyMocks.deleteDeviceKey).not.toHaveBeenCalled();
  });
});
