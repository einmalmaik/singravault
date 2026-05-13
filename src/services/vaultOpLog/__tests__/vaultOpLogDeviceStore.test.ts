// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it, beforeEach } from 'vitest';
import {
  saveVaultOpLogDeviceIdentity,
  loadVaultOpLogDeviceIdentity,
  clearVaultOpLogDeviceIdentity,
} from '../vaultOpLogDeviceStore';

describe('vaultOpLogDeviceStore', () => {
  beforeEach(() => {
    clearVaultOpLogDeviceIdentity();
  });

  it('round-trips device identity', () => {
    const identity = {
      deviceId: 'device-123',
      publicSigningKeyB64Url: 'abc123',
    };

    saveVaultOpLogDeviceIdentity(identity);
    const loaded = loadVaultOpLogDeviceIdentity();

    expect(loaded).toEqual(identity);
  });

  it('returns null when no identity is stored', () => {
    const loaded = loadVaultOpLogDeviceIdentity();
    expect(loaded).toBeNull();
  });

  it('returns null after clearing', () => {
    saveVaultOpLogDeviceIdentity({ deviceId: 'd', publicSigningKeyB64Url: 'k' });
    clearVaultOpLogDeviceIdentity();
    expect(loadVaultOpLogDeviceIdentity()).toBeNull();
  });

  it('does not store secrets (vaultEncryptionKey not present)', () => {
    const identity = {
      deviceId: 'device-123',
      publicSigningKeyB64Url: 'pubkey',
    };

    saveVaultOpLogDeviceIdentity(identity);
    const raw = localStorage.getItem('singra_vault_oplog_device_identity');
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!);
    expect(parsed).not.toHaveProperty('vaultEncryptionKey');
    expect(parsed).not.toHaveProperty('privateKey');
    expect(parsed).not.toHaveProperty('deviceSigningKey');
  });
});
