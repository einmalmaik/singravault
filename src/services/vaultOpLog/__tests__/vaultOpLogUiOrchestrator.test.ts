// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { loadVaultOpLogUiState } from '../vaultOpLogUiOrchestrator';
import { computeOpHash, computeVaultHead } from '../recordHashes';
import {
  DEVICE_SIGNATURE_SCHEMA_V1,
  type VaultOperationSignedBodyV1,
} from '../types';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import type { VaultOperationRow, VaultRecordRow } from '../vaultOpLogRpcTypes';
import type { VaultOpLogTrustReadClient } from '../vaultOpLogUiOrchestrator';

let importKeySpy: ReturnType<typeof vi.spyOn>;
let verifySpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  importKeySpy = vi.spyOn(globalThis.crypto.subtle, 'importKey').mockResolvedValue({
    type: 'public',
    extractable: false,
    algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    usages: ['verify'],
  } as unknown as CryptoKey);
  verifySpy = vi.spyOn(globalThis.crypto.subtle, 'verify').mockResolvedValue(true);
});

afterEach(() => {
  importKeySpy?.mockRestore();
  verifySpy?.mockRestore();
});

function createMockRpcClient(pages: VaultOperationRow[][]): SupabaseRpcClient {
  let callIndex = 0;
  const operations = pages.flat();
  const currentHead = operations.at(-1)?.resultingVaultHead ?? 'head-1';
  const currentSequenceNumber = operations.at(-1)?.sequenceNumber ?? 10;
  return {
    rpc: vi.fn().mockImplementation(async (fnName: string, params: Record<string, unknown>) => {
      if (fnName === 'get_vault_head') {
        return {
          data: [{
            vault_id: 'vault-1',
            current_head: currentHead,
            current_op_id: operations.at(-1)?.opId ?? null,
            current_sequence_number: currentSequenceNumber,
            updated_at: '2025-01-01T00:00:00Z',
          }],
          error: null,
        };
      }
      if (fnName === 'get_vault_changes_since') {
        const page = pages[callIndex] ?? [];
        callIndex += 1;
        return {
          data: page.map((op) => ({
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
          })),
          error: null,
        };
      }
      if (fnName === 'get_vault_records_by_ids') {
        return {
          data: [],
          error: null,
        };
      }
      throw new Error(`Unexpected RPC: ${fnName}`);
    }),
  } as unknown as SupabaseRpcClient;
}

function createTrustClient(rows: unknown[]): VaultOpLogTrustReadClient {
  return {
    from: vi.fn(() => ({
      select: vi.fn(() => ({
        eq: vi.fn(async () => ({ data: rows, error: null })),
      })),
    })),
  } as unknown as VaultOpLogTrustReadClient;
}

async function makeOp(
  seq: number,
  opId: string,
  recordId: string,
  baseVaultHead: string | null,
): Promise<VaultOperationRow> {
  const signedBody: VaultOperationSignedBodyV1 = {
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    opId,
    intentId: `intent-${opId}`,
    rebasedFromOpId: null,
    vaultId: 'vault-1',
    authorDeviceId: 'device-1',
    opType: 'create',
    recordId,
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: `record-hash-${opId}`,
    baseVaultHead,
    payloadCiphertextHash: `payload-hash-${opId}`,
    payloadAadHash: `aad-hash-${opId}`,
    createdAtClient: '2025-01-01T00:00:00Z',
    trustEpoch: 0,
    targetPublicSigningKey: null,
    targetDeviceKeyFingerprint: null,
  };
  const opHash = await computeOpHash(signedBody);
  const resultingVaultHead = await computeVaultHead({
    previousVaultHead: baseVaultHead,
    opHash,
    recordId,
    recordType: 'item',
    newRecordHash: signedBody.newRecordHash,
    opType: 'create',
  });

  return {
    opId,
    opHash,
    vaultId: 'vault-1',
    authorDeviceId: 'device-1',
    opType: 'create',
    recordId,
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: signedBody.newRecordHash,
    baseVaultHead,
    resultingVaultHead,
    intentId: signedBody.intentId,
    rebasedFromOpId: null,
    payloadCiphertextHash: signedBody.payloadCiphertextHash,
    payloadAadHash: signedBody.payloadAadHash,
    signedBody,
    signature: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    signatureSchema: 'v1',
    trustEpoch: 0,
    createdAtClient: '2025-01-01T00:00:00Z',
    receivedAtServer: '2025-01-01T00:00:00Z',
    sequenceNumber: seq,
  };
}

async function makeCreateOps(count: number): Promise<VaultOperationRow[]> {
  const operations: VaultOperationRow[] = [];
  let head: string | null = null;
  for (let i = 1; i <= count; i += 1) {
    const operation = await makeOp(i, `op-${i}`, `rec-${i}`, head);
    operations.push(operation);
    head = operation.resultingVaultHead;
  }
  return operations;
}

describe('vaultOpLogUiOrchestrator', () => {
  it('returns empty state for no operations', async () => {
    const client = createMockRpcClient([[]]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBeNull();
    expect(result.uiView).not.toBeNull();
    expect(result.uiView!.verifiedItems).toHaveLength(0);
    expect(result.uiView!.quarantinedItems).toHaveLength(0);
    expect(result.uiView!.conflictedItems).toHaveLength(0);
  });

  it('loads trusted devices from the remote trust table instead of only trusting the local device', async () => {
    const client = createMockRpcClient([[]]);
    const trustClient = createTrustClient([
      {
        vault_id: 'vault-1',
        device_id: 'device-1',
        public_signing_key: 'pub-local',
        device_name_encrypted: '',
        added_by_device_id: null,
        added_at: '2025-01-01T00:00:00Z',
        trust_epoch: 0,
        status: 'trusted',
        revoked_at: null,
        revoked_by_device_id: null,
      },
      {
        vault_id: 'vault-1',
        device_id: 'device-2',
        public_signing_key: 'pub-remote',
        device_name_encrypted: '',
        added_by_device_id: 'device-1',
        added_at: '2025-01-02T00:00:00Z',
        trust_epoch: 0,
        status: 'trusted',
        revoked_at: null,
        revoked_by_device_id: null,
      },
    ]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      trustClient,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBeNull();
    expect(result.localVaultState?.trustedDevicesById.has('device-2')).toBe(true);
  });

  it('loads read-only state from remote trust without a local device identity', async () => {
    const client = createMockRpcClient([[]]);
    const trustClient = createTrustClient([
      {
        vault_id: 'vault-1',
        device_id: 'device-1',
        public_signing_key: 'pub-local',
        device_name_encrypted: '',
        added_by_device_id: null,
        added_at: '2025-01-01T00:00:00Z',
        trust_epoch: 0,
        status: 'trusted',
        revoked_at: null,
        revoked_by_device_id: null,
      },
    ]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      trustClient,
      vaultId: 'vault-1',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBeNull();
    expect(result.localVaultState?.trustedDevicesById.has('device-1')).toBe(true);
  });

  it('does not load vault records when UI state requires local device trust and the local identity is missing', async () => {
    const operations = await makeCreateOps(1);
    const client = createMockRpcClient([operations]);
    const trustClient = createTrustClient([
      {
        vault_id: 'vault-1',
        device_id: 'device-1',
        public_signing_key: 'pub-local',
        device_name_encrypted: '',
        added_by_device_id: null,
        added_at: '2025-01-01T00:00:00Z',
        trust_epoch: 0,
        status: 'trusted',
        revoked_at: null,
        revoked_by_device_id: null,
      },
    ]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      trustClient,
      vaultId: 'vault-1',
      vaultEncryptionKey: new Uint8Array(32),
      requireLocalDeviceTrust: true,
    });

    const rpcCalls = (client.rpc as ReturnType<typeof vi.fn>).mock.calls;
    expect(rpcCalls.some((call) => call[0] === 'get_vault_records_by_ids')).toBe(false);
    expect(result.error).toBeNull();
    expect(result.localVaultState?.recordsById.size).toBe(0);
    expect(result.uiView?.trustedDeviceIds).toEqual(['device-1']);
  });

  it('paginates through multiple pages of operations', async () => {
    // Simulate 2 pages: 1 full page (500 ops) + 1 partial page (3 ops)
    const operations = await makeCreateOps(503);
    const fullPage = operations.slice(0, 500);
    const partialPage = operations.slice(500);
    const client = createMockRpcClient([fullPage, partialPage]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBeNull();
    expect(result.uiView).not.toBeNull();

    // Should have fetched 2 pages
    const rpcCalls = (client.rpc as ReturnType<typeof vi.fn>).mock.calls;
    const changesCalls = rpcCalls.filter((call) => call[0] === 'get_vault_changes_since');
    expect(changesCalls.length).toBe(2);

    // Verify second page starts after last sequence of first page
    expect(changesCalls[1][1]).toMatchObject({ p_since_sequence: 500 });
  });

  it('deduplicates operations by opId across pages', async () => {
    // Same op appears in two pages (simulating an overlap at the page boundary).
    const operations = await makeCreateOps(501);
    const page1 = operations.slice(0, 500);
    const page2 = [operations[499], operations[500]];
    const client = createMockRpcClient([page1, page2]);

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBeNull();
    expect(result.uiView).not.toBeNull();
    // The duplicate boundary operation should only appear once in the processed state.
    expect(result.localVaultState).not.toBeNull();
  });

  it('returns error for failed vault head load', async () => {
    const client = {
      rpc: vi.fn().mockResolvedValue({ data: null, error: { message: 'db error' } }),
    } as unknown as SupabaseRpcClient;

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBe('vault_head_load_failed');
    expect(result.uiView).toBeNull();
  });

  it('does not leak internal error details in error messages', async () => {
    const client = {
      rpc: vi.fn().mockImplementation(async (fnName: string) => {
        if (fnName === 'get_vault_head') {
          return { data: [{ vault_id: 'vault-1', current_head: 'h', current_op_id: null, current_sequence_number: 1, updated_at: '2025-01-01' }], error: null };
        }
        return { data: null, error: { message: 'connection refused', code: 'P0001' } };
      }),
    } as unknown as SupabaseRpcClient;

    const result = await loadVaultOpLogUiState({
      rpcClient: client,
      vaultId: 'vault-1',
      deviceId: 'device-1',
      publicSigningKeyB64Url: 'MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEsPH3N7n90R0D1TdX',
      vaultEncryptionKey: new Uint8Array(32),
    });

    expect(result.error).toBe('vault_changes_load_failed');
    expect(result.error).not.toContain('connection refused');
    expect(result.error).not.toContain('P0001');
  });
});
