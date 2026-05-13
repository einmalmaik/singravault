// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { useVaultRevokedDeviceAutoLock } from './useVaultRevokedDeviceAutoLock';
import {
  loadVaultOpLogDeviceIdentity,
  saveVaultOpLogDeviceIdentity,
} from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';

function emptyLocalVaultState(): LocalVaultState {
  return {
    recordsById: new Map(),
    quarantinedRecordsById: new Map(),
    conflictsByRecordId: new Map(),
    trustedDevicesById: new Map(),
    lastVerifiedVaultHead: null,
  };
}

describe('useVaultRevokedDeviceAutoLock', () => {
  it('locks and clears local device identity when the current device is revoked', async () => {
    saveVaultOpLogDeviceIdentity({
      deviceId: 'device-revoked',
      publicSigningKeyB64Url: 'public-key',
    });
    const lock = vi.fn();
    const localVaultState = emptyLocalVaultState();
    localVaultState.trustedDevicesById.set('device-revoked', {
      vaultId: 'vault-1',
      deviceId: 'device-revoked',
      publicSigningKey: 'public-key',
      deviceNameEncrypted: '',
      addedByDeviceId: null,
      addedAt: '2026-05-12T10:00:00.000Z',
      trustEpoch: 1,
      status: 'revoked',
      revokedAt: '2026-05-12T10:05:00.000Z',
      revokedByDeviceId: 'device-other',
    });

    renderHook(() => useVaultRevokedDeviceAutoLock({
      isLocked: false,
      localVaultState,
      lock,
      vaultMigrationStatus: 'verified',
    }));

    await waitFor(() => {
      expect(lock).toHaveBeenCalledTimes(1);
    });
    expect(loadVaultOpLogDeviceIdentity()).toBeNull();
  });

  it('does not clear identity or lock while the current device is still trusted', async () => {
    saveVaultOpLogDeviceIdentity({
      deviceId: 'device-trusted',
      publicSigningKeyB64Url: 'public-key',
    });
    const lock = vi.fn();
    const localVaultState = emptyLocalVaultState();
    localVaultState.trustedDevicesById.set('device-trusted', {
      vaultId: 'vault-1',
      deviceId: 'device-trusted',
      publicSigningKey: 'public-key',
      deviceNameEncrypted: '',
      addedByDeviceId: null,
      addedAt: '2026-05-12T10:00:00.000Z',
      trustEpoch: 1,
      status: 'trusted',
      revokedAt: null,
      revokedByDeviceId: null,
    });

    renderHook(() => useVaultRevokedDeviceAutoLock({
      isLocked: false,
      localVaultState,
      lock,
      vaultMigrationStatus: 'verified',
    }));

    await waitFor(() => {
      expect(lock).not.toHaveBeenCalled();
    });
    expect(loadVaultOpLogDeviceIdentity()).toEqual({
      deviceId: 'device-trusted',
      publicSigningKeyB64Url: 'public-key',
    });
  });
});
