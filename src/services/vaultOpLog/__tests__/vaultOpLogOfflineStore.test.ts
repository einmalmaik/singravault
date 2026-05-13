// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { beforeEach, describe, expect, it } from 'vitest';
import {
  listVerifiedVaultOpLogOfflineCachesForUser,
  loadVerifiedVaultOpLogOfflineCache,
  saveVerifiedVaultOpLogOfflineCache,
} from '../vaultOpLogOfflineStore';
import { DEVICE_SIGNATURE_SCHEMA_V1, type TrustedDeviceRecordV1 } from '../types';
import type { VaultOperationRow, VaultRecordRow } from '../vaultOpLogRpcTypes';

const USER_ID = 'user-offline-cache';
const VAULT_ID = 'vault-offline-cache';

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

let fakeDb: FakeIDBDatabase;

beforeEach(() => {
  fakeDb = new FakeIDBDatabase();
  const idb = globalThis.indexedDB as unknown as Record<string, unknown>;
  idb.open = () => new FakeIDBRequest(fakeDb, true);
});

describe('vaultOpLogOfflineStore', () => {
  it('stores and reloads only verified OpLog rows, sealed records and public trust metadata', async () => {
    await saveVerifiedVaultOpLogOfflineCache({
      userId: USER_ID,
      vaultId: VAULT_ID,
      currentHead: 'head-1',
      currentSequenceNumber: 1,
      operations: [operationRow()],
      records: [recordRow()],
      trustedDevices: [trustedDevice()],
    });

    const loaded = await loadVerifiedVaultOpLogOfflineCache({ userId: USER_ID, vaultId: VAULT_ID });

    expect(loaded?.currentHead).toBe('head-1');
    expect(loaded?.operations).toHaveLength(1);
    expect(loaded?.records).toHaveLength(1);
    expect(loaded?.trustedDevices).toHaveLength(1);
    const serialized = JSON.stringify(loaded);
    expect(serialized).not.toContain('plaintext-value');
    expect(serialized).not.toContain('private-signing-key');
    expect(serialized).not.toContain('master-password');
    expect(serialized).not.toContain('device-key-secret');
  });

  it('rejects cache entries for another user or vault', async () => {
    await saveVerifiedVaultOpLogOfflineCache({
      userId: USER_ID,
      vaultId: VAULT_ID,
      currentHead: 'head-1',
      currentSequenceNumber: 1,
      operations: [operationRow()],
      records: [recordRow()],
      trustedDevices: [trustedDevice()],
    });

    await expect(loadVerifiedVaultOpLogOfflineCache({
      userId: 'other-user',
      vaultId: VAULT_ID,
    })).resolves.toBeNull();
    await expect(loadVerifiedVaultOpLogOfflineCache({
      userId: USER_ID,
      vaultId: 'other-vault',
    })).resolves.toBeNull();
  });

  it('lists only valid verified cache entries for the current user', async () => {
    await saveVerifiedVaultOpLogOfflineCache({
      userId: USER_ID,
      vaultId: VAULT_ID,
      currentHead: 'head-1',
      currentSequenceNumber: 1,
      operations: [operationRow()],
      records: [recordRow()],
      trustedDevices: [trustedDevice()],
    });
    await saveVerifiedVaultOpLogOfflineCache({
      userId: 'other-user',
      vaultId: 'other-vault',
      currentHead: 'head-2',
      currentSequenceNumber: 1,
      operations: [operationRow('other-vault')],
      records: [recordRow('other-vault')],
      trustedDevices: [trustedDevice('other-vault')],
    });

    const entries = await listVerifiedVaultOpLogOfflineCachesForUser({ userId: USER_ID });

    expect(entries.map((entry) => entry.vaultId)).toEqual([VAULT_ID]);
  });
});

function operationRow(vaultId = VAULT_ID): VaultOperationRow {
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

function recordRow(vaultId = VAULT_ID): VaultRecordRow {
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

function trustedDevice(vaultId = VAULT_ID): TrustedDeviceRecordV1 {
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
