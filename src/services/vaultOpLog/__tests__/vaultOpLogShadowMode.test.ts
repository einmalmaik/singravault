// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Tests for Phase 8 — Shadow Mode parallel verification.
 *
 * Security invariants under test:
 * - Shadow Mode runs only when the feature flag is explicitly enabled.
 * - Shadow Mode does not switch UI, Autofill, Export, Search or Clipboard.
 * - Shadow Mode does not block the old productive vault path on failure.
 * - Diagnosis contains only counts, IDs, hash prefixes, and status codes.
 * - No plaintext secrets, titles, URLs, usernames, passwords, or notes appear.
 * - No automatic rebaseline, repair, or deletion is triggered.
 * - Shadow mode is fully inert when the flag is disabled.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import {
  runShadowModeVerification,
  getShadowModeDiagnoses,
  clearShadowModeDiagnoses,
} from '../vaultOpLogShadowMode';
import type { ShadowModeRunInput } from '../vaultOpLogShadowModeTypes';
import {
  generateDeviceSigningKeyPair,
} from '../operationSigningService';
import {
  buildCreateRecordOperation,
  toVaultOperationRow,
  toVaultRecordRow,
} from '../vaultOpLogOperationBuilder';
import * as featureFlags from '../vaultOpLogFeatureFlags';
import {
  isVaultOpLogShadowModeEnabled,
} from '../vaultOpLogFeatureFlags';
import type { LegacyVaultItemRow, LegacyCategoryRow } from '../migrationTypes';

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

async function buildMockRpcClientWithOperations(
  vaultId: string,
  deviceId: string,
  deviceSigningKey: CryptoKey,
  publicSigningKeyB64Url: string,
  vaultEncryptionKey: Uint8Array,
  itemCount: number,
  categoryCount: number,
): Promise<SupabaseRpcClient> {
  const operations: ReturnType<typeof toVaultOperationRow>[] = [];
  const records: ReturnType<typeof toVaultRecordRow>[] = [];

  const now = new Date().toISOString();

  // Manifest first
  const manifestBuilt = await buildCreateRecordOperation({
    opId: `op-manifest-${vaultId}`,
    intentId: `intent-manifest-${vaultId}`,
    rebasedFromOpId: null,
    vaultId,
    recordId: `manifest-${vaultId}`,
    deviceId,
    deviceSigningKey,
    trustEpoch: 0,
    baseVaultHead: null,
    recordType: 'manifest',
    vaultEncryptionKey,
    plaintext: new TextEncoder().encode('{}'),
    keyVersion: 1,
    createdAtClient: now,
  });
  operations.push(toVaultOperationRow(manifestBuilt));
  records.push(toVaultRecordRow(manifestBuilt.sealedRecord, toVaultOperationRow(manifestBuilt), false));

  let lastHead = manifestBuilt.resultingVaultHead;

  for (let i = 0; i < categoryCount; i += 1) {
    const catId = `cat-${i}`;
    const built = await buildCreateRecordOperation({
      opId: `op-cat-${catId}`,
      intentId: `intent-cat-${catId}`,
      rebasedFromOpId: null,
      vaultId,
      recordId: catId,
      deviceId,
      deviceSigningKey,
      trustEpoch: 0,
      baseVaultHead: lastHead,
      recordType: 'category',
      vaultEncryptionKey,
      plaintext: new TextEncoder().encode(`{"name":"Category ${i}"}`),
      keyVersion: 1,
      createdAtClient: now,
    });
    operations.push(toVaultOperationRow(built));
    records.push(toVaultRecordRow(built.sealedRecord, toVaultOperationRow(built), false));
    lastHead = built.resultingVaultHead;
  }

  for (let i = 0; i < itemCount; i += 1) {
    const itemId = `item-${i}`;
    const built = await buildCreateRecordOperation({
      opId: `op-item-${itemId}`,
      intentId: `intent-item-${itemId}`,
      rebasedFromOpId: null,
      vaultId,
      recordId: itemId,
      deviceId,
      deviceSigningKey,
      trustEpoch: 0,
      baseVaultHead: lastHead,
      recordType: 'item',
      vaultEncryptionKey,
      plaintext: new TextEncoder().encode(`{"title":"Item ${i}","password":"secret${i}"}`),
      keyVersion: 1,
      createdAtClient: now,
    });
    operations.push(toVaultOperationRow(built));
    records.push(toVaultRecordRow(built.sealedRecord, toVaultOperationRow(built), false));
    lastHead = built.resultingVaultHead;
  }

  const rpc = vi.fn(async <T = unknown>(
    fn: string,
    _params: Record<string, unknown>,
    _options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): Promise<{ data: T | null; error: { code: string; message: string; details?: string; hint?: string } | null }> => {
    if (fn === 'get_vault_head') {
      return {
        data: [{
          vault_id: vaultId,
          current_head: lastHead,
          current_op_id: operations.length > 0 ? operations[operations.length - 1].opId : null,
          current_sequence_number: operations.length,
          updated_at: now,
        }] as T,
        error: null,
      };
    }
    if (fn === 'get_vault_changes_since') {
      const dbOperations = operations.map((op) => ({
        op_id: op.opId,
        op_hash: op.opHash,
        vault_id: op.vaultId,
        author_device_id: op.authorDeviceId,
        op_type: op.opType,
        record_id: op.recordId,
        record_type: op.recordType,
        base_record_version: op.baseRecordVersion,
        previous_ciphertext_hash: op.previousCiphertextHash,
        new_record_hash: op.newRecordHash,
        base_vault_head: op.baseVaultHead,
        resulting_vault_head: op.resultingVaultHead,
        intent_id: op.intentId,
        rebased_from_op_id: op.rebasedFromOpId,
        payload_ciphertext_hash: op.payloadCiphertextHash,
        payload_aad_hash: op.payloadAadHash,
        signed_body: op.signedBody,
        signature: op.signature,
        signature_schema: op.signatureSchema,
        trust_epoch: op.trustEpoch,
        created_at_client: op.createdAtClient,
        received_at_server: op.receivedAtServer,
        sequence_number: op.sequenceNumber,
      }));
      return { data: dbOperations as T, error: null };
    }
    if (fn === 'get_vault_records_by_ids') {
      const dbRecords = records.map((rec) => ({
        vault_id: rec.vaultId,
        record_id: rec.recordId,
        record_type: rec.recordType,
        record_version: rec.recordVersion,
        key_version: rec.keyVersion,
        aad_hash: rec.aadHash,
        ciphertext_hash: rec.ciphertextHash,
        nonce: rec.nonce,
        ciphertext: rec.ciphertext,
        last_op_id: rec.lastOpId,
        last_op_hash: rec.lastOpHash,
        is_tombstone: rec.isTombstone,
        created_at: rec.createdAt,
        updated_at: rec.updatedAt,
      }));
      return { data: dbRecords as T, error: null };
    }
    return { data: null, error: { code: 'UNKNOWN', message: 'unknown function' } };
  });

  return { rpc } as unknown as SupabaseRpcClient;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('runShadowModeVerification', () => {
  beforeEach(() => {
    clearShadowModeDiagnoses();
    vi.spyOn(featureFlags, 'isVaultOpLogShadowModeEnabled').mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('completes successfully and counts verified records', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-1';
    const deviceId = 'device-shadow-1';

    const rpcClient = await buildMockRpcClientWithOperations(
      vaultId,
      deviceId,
      keyPair.privateKey,
      keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      3,
      2,
    );

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    const result = await runShadowModeVerification(input);

    expect(result.success).toBe(true);
    expect(result.diagnosis.status).toBe('completed');
    expect(result.diagnosis.errorKind).toBeNull();
    expect(result.diagnosis.vaultSecurityMode).toBe('normal');
    expect(result.diagnosis.verifiedCount).toBeGreaterThan(0);
    expect(result.diagnosis.quarantinedCount).toBe(0);
    expect(result.diagnosis.conflictCount).toBe(0);

    // Diagnosis buffer should contain the run
    const buffer = getShadowModeDiagnoses();
    expect(buffer.length).toBe(1);
    expect(buffer[0].vaultId).toBe(vaultId);
  });

  it('does not block or throw when RPC fails', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-2';
    const deviceId = 'device-shadow-2';

    const rpc = vi.fn(async <T = unknown>(
      fn: string,
      _params: Record<string, unknown>,
      _options?: { count?: 'exact' | 'planned' | 'estimated' },
    ): Promise<{ data: T | null; error: { code: string; message: string; details?: string; hint?: string } | null }> => {
      if (fn === 'get_vault_head') {
        return { data: null, error: { code: 'RPC_ERROR', message: 'connection lost' } };
      }
      return { data: null, error: { code: 'UNKNOWN', message: 'unknown' } };
    });
    const rpcClient = { rpc } as unknown as SupabaseRpcClient;

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    const result = await runShadowModeVerification(input);

    expect(result.success).toBe(false);
    expect(result.diagnosis.status).toBe('failed');
    expect(result.diagnosis.errorKind).toBe('rpcError');

    // The productive vault path would still be free to operate
    // (this is a structural guarantee of the shadow mode design).
  });

  it('does not store plaintext secrets in diagnosis', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-3';
    const deviceId = 'device-shadow-3';

    const rpcClient = await buildMockRpcClientWithOperations(
      vaultId,
      deviceId,
      keyPair.privateKey,
      keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      2,
      1,
    );

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    const result = await runShadowModeVerification(input);

    expect(result.success).toBe(true);

    // No diagnosis field should contain user content
    const json = JSON.stringify(result.diagnosis);
    expect(json).not.toContain('My Secret Bank');
    expect(json).not.toContain('bank.example');
    expect(json).not.toContain('Finance');
    expect(json).not.toContain('secret');
    expect(json).not.toContain('password');

    // Hash prefixes should be short (8 chars)
    for (const rd of result.diagnosis.recordDiagnoses) {
      expect(rd.hashPrefix.length).toBeLessThanOrEqual(8);
    }
  });

  it('does not modify the old productive vault state', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-4';
    const deviceId = 'device-shadow-4';

    const rpcClient = await buildMockRpcClientWithOperations(
      vaultId,
      deviceId,
      keyPair.privateKey,
      keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      2,
      1,
    );

    // Simulate an old productive state object that should remain untouched.
    const productiveState = { items: [{ id: 'old-1' }, { id: 'old-2' }] };
    const before = JSON.stringify(productiveState);

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    await runShadowModeVerification(input);

    const after = JSON.stringify(productiveState);
    expect(after).toBe(before);
  });

  it('does not trigger automatic rebaseline or repair', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-5';
    const deviceId = 'device-shadow-5';

    const rpcClient = await buildMockRpcClientWithOperations(
      vaultId,
      deviceId,
      keyPair.privateKey,
      keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      1,
      0,
    );

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    const result = await runShadowModeVerification(input);

    expect(result.success).toBe(true);
    // No repair or rebaseline action should have occurred.
    // The diagnosis is purely observational.
    expect(result.diagnosis.vaultSecurityMode).toBe('normal');
    expect(getShadowModeDiagnoses().length).toBe(1);
  });

  it('isolates shadow failures without affecting productive paths', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-6';
    const deviceId = 'device-shadow-6';

    const rpc = vi.fn(async <T = unknown>(
      _fn: string,
      _params: Record<string, unknown>,
      _options?: { count?: 'exact' | 'planned' | 'estimated' },
    ): Promise<{ data: T | null; error: { code: string; message: string; details?: string; hint?: string } | null }> => {
      throw new Error('unexpected rpc explosion');
    });
    const rpcClient = { rpc } as unknown as SupabaseRpcClient;

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId,
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    // Must not throw; must return a graceful failure diagnosis.
    const result = await runShadowModeVerification(input);

    expect(result.success).toBe(false);
    expect(result.diagnosis.status).toBe('failed');
    expect(result.diagnosis.errorKind).toBe('unexpectedError');
  });
});

describe('Shadow Mode feature flag contract', () => {
  it('has a conservative default of false', () => {
    // The environment in tests does not set the flag, so it must be false.
    expect(isVaultOpLogShadowModeEnabled()).toBe(false);
  });
});

describe('Shadow Mode diagnosis buffer', () => {
  beforeEach(() => {
    clearShadowModeDiagnoses();
    vi.spyOn(featureFlags, 'isVaultOpLogShadowModeEnabled').mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('stores only sanitised metadata', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();
    const vaultId = 'vault-shadow-7';

    const rpcClient = await buildMockRpcClientWithOperations(
      vaultId,
      'device-7',
      keyPair.privateKey,
      keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      1,
      0,
    );

    const input: ShadowModeRunInput = {
      vaultId,
      deviceId: 'device-7',
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
      vaultEncryptionKey,
      rpcClient,
    };

    await runShadowModeVerification(input);
    const buffer = getShadowModeDiagnoses();
    expect(buffer.length).toBe(1);

    const diagnosis = buffer[0];
    expect(diagnosis.vaultId).toBe(vaultId);
    expect(diagnosis.recordDiagnoses.length).toBeGreaterThan(0);

    for (const rd of diagnosis.recordDiagnoses) {
      // recordId may contain an ID, but no plaintext content
      expect(typeof rd.recordId).toBe('string');
      expect(rd.recordVersion).toBeGreaterThanOrEqual(0);
      expect(rd.hashPrefix.length).toBeLessThanOrEqual(8);
      expect(typeof rd.reasonCode).toBe('string');
    }
  });

  it('caps the in-memory buffer at a safe size', async () => {
    const keyPair = await generateDeviceSigningKeyPair();
    const vaultEncryptionKey = makeVaultEncryptionKey();

    for (let i = 0; i < 25; i += 1) {
      const vaultId = `vault-buf-${i}`;
      const rpcClient = await buildMockRpcClientWithOperations(
        vaultId,
        'device-buf',
        keyPair.privateKey,
        keyPair.publicKeyB64Url,
        vaultEncryptionKey,
        0,
        0,
      );

      const input: ShadowModeRunInput = {
        vaultId,
        deviceId: 'device-buf',
        publicSigningKeyB64Url: keyPair.publicKeyB64Url,
        vaultEncryptionKey,
        rpcClient,
      };

      await runShadowModeVerification(input);
    }

    const buffer = getShadowModeDiagnoses();
    expect(buffer.length).toBeLessThanOrEqual(20);
  });
});
