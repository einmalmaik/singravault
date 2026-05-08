// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import {
  CategoryStillReferencedError,
  MissingVerifiedBaseMetadataError,
  OperationSubmissionRetryableError,
  createCategory,
  createItem,
  deleteCategory,
  deleteCategoryAndReferencedItems,
  deleteCategoryAndUnlinkItems,
  deleteItem,
  resolveConflict,
  restoreRecord,
  updateCategory,
  updateItem,
  type CategoryPlaintext,
  type ItemPlaintext,
  type VaultOpLogCrudServiceDependencies,
  type VerifiedRecordBase,
} from '../vaultOpLogCrudService';
import { generateDeviceSigningKeyPair } from '../operationSigningService';
import { InMemoryQueuePersistence } from '../vaultOpLogQueuePersistence';
import { loadVaultOpLogUiState } from '../vaultOpLogUiOrchestrator';
import type { SupabaseRpcClient } from '../vaultOpLogRepository';
import type { LocalVaultState, LocalVerifiedRecord } from '../vaultStateMachine';

const VAULT_ID = 'vault-crud-1';
const USER_ID = 'user-crud-1';
const DEVICE_ID = 'device-crud-1';
const INITIAL_HEAD = 'head-0';

interface FakeOperationRow {
  op_id: string;
  op_hash: string;
  vault_id: string;
  author_device_id: string;
  op_type: string;
  record_id: string;
  record_type: string;
  base_record_version: number | null;
  previous_ciphertext_hash: string | null;
  new_record_hash: string | null;
  base_vault_head: string | null;
  resulting_vault_head: string;
  intent_id: string | null;
  rebased_from_op_id: string | null;
  payload_ciphertext_hash: string | null;
  payload_aad_hash: string | null;
  signed_body: unknown;
  signature: string;
  signature_schema: string;
  trust_epoch: number;
  created_at_client: string;
  received_at_server: string;
  sequence_number: number;
}

interface FakeRecordRow {
  vault_id: string;
  record_id: string;
  record_type: string;
  record_version: number;
  key_version: number;
  aad_hash: string;
  ciphertext_hash: string;
  nonce: string;
  ciphertext: string;
  last_op_id: string;
  last_op_hash: string;
  is_tombstone: boolean;
  created_at: string;
  updated_at: string;
}

class FakeRpcClient implements SupabaseRpcClient {
  head = INITIAL_HEAD;
  sequence = 0;
  operations: FakeOperationRow[] = [];
  records = new Map<string, FakeRecordRow>();
  lastSubmitParams: Record<string, unknown> | null = null;
  failNextSubmit = false;

  async rpc<T = unknown>(
    fn: string,
    params: Record<string, unknown>,
  ): Promise<{ data: T | null; error: { code: string; message: string } | null }> {
    if (fn === 'submit_vault_operation') {
      this.lastSubmitParams = params;
      if (this.failNextSubmit) {
        this.failNextSubmit = false;
        return {
          data: null,
          error: { code: '503', message: 'temporary unavailable' },
        };
      }
      return { data: this.submit(params) as T, error: null };
    }

    if (fn === 'get_vault_head') {
      return {
        data: [{
          vault_id: VAULT_ID,
          current_head: this.head,
          current_op_id: this.operations.at(-1)?.op_id ?? null,
          current_sequence_number: this.sequence,
          updated_at: '2026-05-06T00:00:00.000Z',
        }] as T,
        error: null,
      };
    }

    if (fn === 'get_vault_changes_since') {
      const since = Number(params.p_since_sequence ?? 0);
      return {
        data: this.operations.filter((operation) => operation.sequence_number > since) as T,
        error: null,
      };
    }

    if (fn === 'get_vault_records_by_ids') {
      const ids = Array.isArray(params.p_record_ids) ? params.p_record_ids : [];
      return {
        data: ids.flatMap((id) => {
          const row = this.records.get(String(id));
          return row ? [row] : [];
        }) as T,
        error: null,
      };
    }

    return {
      data: null,
      error: { code: '404', message: `unknown rpc ${fn}` },
    };
  }

  private submit(params: Record<string, unknown>): Record<string, unknown> {
    const op = params.p_op as Record<string, unknown>;
    const payload = params.p_record_payload as Record<string, unknown> | null;
    if (!payload) {
      throw new Error('test fake requires record payload');
    }

    this.sequence += 1;
    const operation: FakeOperationRow = {
      op_id: String(op.op_id),
      op_hash: String(op.op_hash),
      vault_id: String(op.vault_id),
      author_device_id: String(op.author_device_id),
      op_type: String(op.op_type),
      record_id: String(op.record_id),
      record_type: String(op.record_type),
      base_record_version: op.base_record_version as number | null,
      previous_ciphertext_hash: op.previous_ciphertext_hash as string | null,
      new_record_hash: op.new_record_hash as string | null,
      base_vault_head: op.base_vault_head as string | null,
      resulting_vault_head: String(op.resulting_vault_head),
      intent_id: op.intent_id as string | null,
      rebased_from_op_id: op.rebased_from_op_id as string | null,
      payload_ciphertext_hash: op.payload_ciphertext_hash as string | null,
      payload_aad_hash: op.payload_aad_hash as string | null,
      signed_body: op.signed_body,
      signature: String(op.signature),
      signature_schema: String(op.signature_schema),
      trust_epoch: Number(op.trust_epoch),
      created_at_client: String(op.created_at_client),
      received_at_server: '2026-05-06T00:00:00.000Z',
      sequence_number: this.sequence,
    };

    const existing = this.records.get(operation.record_id);
    const record: FakeRecordRow = {
      vault_id: operation.vault_id,
      record_id: operation.record_id,
      record_type: operation.record_type,
      record_version: existing ? existing.record_version + 1 : 1,
      key_version: Number(payload.key_version),
      aad_hash: String(payload.aad_hash),
      ciphertext_hash: String(payload.ciphertext_hash),
      nonce: String(payload.nonce),
      ciphertext: String(payload.ciphertext),
      last_op_id: operation.op_id,
      last_op_hash: operation.op_hash,
      is_tombstone: operation.op_type === 'delete',
      created_at: existing?.created_at ?? operation.created_at_client,
      updated_at: operation.created_at_client,
    };

    this.operations.push(operation);
    this.records.set(operation.record_id, record);
    this.head = operation.resulting_vault_head;

    return {
      applied: true,
      idempotent: false,
      op_id: operation.op_id,
      sequence_number: operation.sequence_number,
      resulting_vault_head: operation.resulting_vault_head,
      current_head: this.head,
      current_sequence_number: this.sequence,
      conflict_reason: null,
    };
  }
}

async function deps(rpcClient: FakeRpcClient, queuePersistence = new InMemoryQueuePersistence()): Promise<VaultOpLogCrudServiceDependencies> {
  const keyPair = await generateDeviceSigningKeyPair();
  return {
    vaultId: VAULT_ID,
    userId: USER_ID,
    deviceId: DEVICE_ID,
    deviceSigningKey: keyPair.privateKey,
    publicSigningKeyB64Url: keyPair.publicKeyB64Url,
    vaultEncryptionKey: crypto.getRandomValues(new Uint8Array(32)),
    trustEpoch: 0,
    keyVersion: 1,
    rpcClient,
    queuePersistence,
  };
}

function itemPlaintext(overrides: Partial<ItemPlaintext> = {}): ItemPlaintext {
  return {
    title: 'Example',
    websiteUrl: 'https://example.com',
    username: 'alice',
    password: 'secret',
    notes: null,
    itemType: 'password',
    categoryRecordId: null,
    isFavorite: false,
    ...overrides,
  };
}

function categoryPlaintext(overrides: Partial<CategoryPlaintext> = {}): CategoryPlaintext {
  return {
    name: 'Work',
    icon: null,
    color: '#3b82f6',
    parentCategoryRecordId: null,
    sortOrder: null,
    ...overrides,
  };
}

function baseFromFake(rpc: FakeRpcClient, recordId: string): VerifiedRecordBase {
  const record = rpc.records.get(recordId);
  if (!record) {
    throw new Error(`missing fake record ${recordId}`);
  }
  return {
    recordVersion: record.record_version,
    ciphertextHash: record.ciphertext_hash,
    baseVaultHead: rpc.head,
  };
}

async function loadLocalState(serviceDeps: VaultOpLogCrudServiceDependencies): Promise<LocalVaultState> {
  const loaded = await loadVaultOpLogUiState({
    rpcClient: serviceDeps.rpcClient,
    vaultId: serviceDeps.vaultId,
    deviceId: serviceDeps.deviceId,
    publicSigningKeyB64Url: serviceDeps.publicSigningKeyB64Url,
    vaultEncryptionKey: serviceDeps.vaultEncryptionKey,
  });
  if (loaded.error || !loaded.localVaultState) {
    throw new Error(loaded.error ?? 'missing local vault state');
  }
  return loaded.localVaultState;
}

function parsePlaintext(record: LocalVerifiedRecord | undefined): Record<string, unknown> {
  if (!record?.plaintext) {
    throw new Error('missing verified plaintext');
  }
  return JSON.parse(new TextDecoder().decode(record.plaintext)) as Record<string, unknown>;
}

describe('vaultOpLogCrudService', () => {
  it('creates an item through submit_vault_operation, queue, reload and verification', async () => {
    const rpc = new FakeRpcClient();
    const queue = new InMemoryQueuePersistence();
    const serviceDeps = await deps(rpc, queue);

    const result = await createItem(serviceDeps, { baseVaultHead: INITIAL_HEAD }, itemPlaintext());

    expect(result.recordId).toBeTruthy();
    expect(rpc.lastSubmitParams).not.toBeNull();
    expect(rpc.operations).toHaveLength(1);
    expect(rpc.operations[0].op_type).toBe('create');
    expect(rpc.records.get(result.recordId)?.is_tombstone).toBe(false);
    expect((await queue.loadAll(VAULT_ID))[0].state).toBe('synced');
  });

  it('fails closed when update base metadata is missing', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);

    await expect(
      updateItem(serviceDeps, 'record-1', null, itemPlaintext()),
    ).rejects.toBeInstanceOf(MissingVerifiedBaseMetadataError);
  });

  it('deletes an item as a signed tombstone payload, not as a direct row delete', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const created = await createItem(serviceDeps, { baseVaultHead: INITIAL_HEAD }, itemPlaintext());

    await deleteItem(serviceDeps, created.recordId, baseFromFake(rpc, created.recordId));

    const submitPayload = rpc.lastSubmitParams?.p_record_payload as Record<string, unknown>;
    expect(submitPayload).toBeTruthy();
    expect(rpc.operations.at(-1)?.op_type).toBe('delete');
    expect(rpc.records.get(created.recordId)?.is_tombstone).toBe(true);
  });

  it('blocks category delete while verified items still reference it', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const created = await createCategory(serviceDeps, { baseVaultHead: INITIAL_HEAD }, categoryPlaintext());

    await expect(
      deleteCategory(serviceDeps, created.recordId, baseFromFake(rpc, created.recordId), ['item-1']),
    ).rejects.toBeInstanceOf(CategoryStillReferencedError);
    expect(rpc.operations).toHaveLength(1);
  });

  it('deletes a category only by unlinking verified items through signed OpLog updates first', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const category = await createCategory(serviceDeps, { baseVaultHead: INITIAL_HEAD }, categoryPlaintext());
    const item = await createItem(
      serviceDeps,
      { baseVaultHead: rpc.head },
      itemPlaintext({ categoryRecordId: category.recordId }),
    );

    await deleteCategoryAndUnlinkItems(serviceDeps, category.recordId);

    const state = await loadLocalState(serviceDeps);
    expect(parsePlaintext(state.recordsById.get(item.recordId)).categoryRecordId).toBeNull();
    expect(state.recordsById.get(category.recordId)?.recordState).toBe('deletedByTrustedDevice');
    expect(rpc.operations.map((operation) => `${operation.record_type}:${operation.op_type}`)).toEqual([
      'category:create',
      'item:create',
      'item:update',
      'category:delete',
    ]);
  });

  it('deletes a category and referenced items as signed tombstone operations', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const category = await createCategory(serviceDeps, { baseVaultHead: INITIAL_HEAD }, categoryPlaintext());
    const item = await createItem(
      serviceDeps,
      { baseVaultHead: rpc.head },
      itemPlaintext({ categoryRecordId: category.recordId }),
    );

    await deleteCategoryAndReferencedItems(serviceDeps, category.recordId);

    const state = await loadLocalState(serviceDeps);
    expect(state.recordsById.get(item.recordId)?.recordState).toBe('deletedByTrustedDevice');
    expect(state.recordsById.get(category.recordId)?.recordState).toBe('deletedByTrustedDevice');
    expect(rpc.operations.map((operation) => `${operation.record_type}:${operation.op_type}`)).toEqual([
      'category:create',
      'item:create',
      'item:delete',
      'category:delete',
    ]);
  });

  it('fails closed when category-delete sequencing lacks verified base metadata', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const category = await createCategory(serviceDeps, { baseVaultHead: INITIAL_HEAD }, categoryPlaintext());
    await createItem(
      serviceDeps,
      { baseVaultHead: rpc.head },
      itemPlaintext({ categoryRecordId: category.recordId }),
    );
    const stateWithoutHead = {
      ...await loadLocalState(serviceDeps),
      lastVerifiedVaultHead: null,
    };

    await expect(
      deleteCategoryAndUnlinkItems(serviceDeps, category.recordId, stateWithoutHead),
    ).rejects.toBeInstanceOf(MissingVerifiedBaseMetadataError);
  });

  it('updates a category through a signed update operation', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const created = await createCategory(serviceDeps, { baseVaultHead: INITIAL_HEAD }, categoryPlaintext());

    await updateCategory(
      serviceDeps,
      created.recordId,
      baseFromFake(rpc, created.recordId),
      categoryPlaintext({ name: 'Private' }),
    );

    expect(rpc.operations.at(-1)?.op_type).toBe('update');
    expect(rpc.operations.at(-1)?.record_type).toBe('category');
  });

  it('restores a record as a signed restore operation from verified snapshot plaintext', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const created = await createItem(serviceDeps, { baseVaultHead: INITIAL_HEAD }, itemPlaintext());
    await deleteItem(serviceDeps, created.recordId, baseFromFake(rpc, created.recordId));

    await restoreRecord(
      serviceDeps,
      created.recordId,
      'item',
      baseFromFake(rpc, created.recordId),
      new TextEncoder().encode(JSON.stringify({ title: 'restored' })),
    );

    expect(rpc.operations.at(-1)?.op_type).toBe('restore');
    expect(rpc.records.get(created.recordId)?.is_tombstone).toBe(false);
  });

  it('keeps retryable submit failures in the pending queue', async () => {
    const rpc = new FakeRpcClient();
    rpc.failNextSubmit = true;
    const queue = new InMemoryQueuePersistence();
    const serviceDeps = await deps(rpc, queue);

    await expect(
      createItem(serviceDeps, { baseVaultHead: INITIAL_HEAD }, itemPlaintext()),
    ).rejects.toBeInstanceOf(OperationSubmissionRetryableError);

    const queued = await queue.loadAll(VAULT_ID);
    expect(queued).toHaveLength(1);
    expect(queued[0].state).toBe('pending');
    expect(queued[0].retryCount).toBe(1);
  });

  it('models conflict resolve as update and does not invent a resolve op type', async () => {
    const rpc = new FakeRpcClient();
    const serviceDeps = await deps(rpc);
    const created = await createItem(serviceDeps, { baseVaultHead: INITIAL_HEAD }, itemPlaintext());

    await resolveConflict(
      serviceDeps,
      created.recordId,
      'item',
      baseFromFake(rpc, created.recordId),
      new TextEncoder().encode(JSON.stringify({ title: 'resolved' })),
    );

    expect(rpc.operations.at(-1)?.op_type).toBe('update');
  });
});
