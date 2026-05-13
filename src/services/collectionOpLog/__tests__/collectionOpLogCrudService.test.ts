// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import { generateDeviceSigningKeyPair } from '@/services/vaultOpLog/operationSigningService';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import {
  CollectionOperationNotVerifiedError,
  MissingCollectionBaseMetadataError,
  getVerifiedCollectionBase,
  submitAndVerifyCollectionMutation,
  type CollectionOpLogCrudDependencies,
} from '../collectionOpLogCrudService';

const COLLECTION_ID = '11111111-1111-4111-8111-111111111111';
const ACTOR_USER_ID = '22222222-2222-4222-8222-222222222222';
const ACTOR_VAULT_ID = '33333333-3333-4333-8333-333333333333';
const DEVICE_ID = '44444444-4444-4444-8444-444444444444';

class FakeCollectionRpcClient implements SupabaseRpcClient {
  currentHead: string | null = null;
  sequence = 0;
  operations: Record<string, unknown>[] = [];
  records = new Map<string, Record<string, unknown>>();
  publicSigningKey = '';
  tamperNextReload = false;
  tamperSignedBodyAfterSubmit = false;
  trustStatus: 'trusted' | 'revoked' = 'trusted';

  async rpc<T = unknown>(
    fn: string,
    params: Record<string, unknown>,
  ): Promise<{ data: T | null; error: { code: string; message: string } | null }> {
    if (fn === 'submit_collection_operation') {
      return { data: this.submit(params) as T, error: null };
    }
    if (fn === 'get_collection_changes_since') {
      return { data: this.operations as T, error: null };
    }
    if (fn === 'get_collection_records_by_ids') {
      const ids = params.p_record_ids as string[];
      const rows = ids.flatMap((id) => {
        const record = this.records.get(id);
        if (!record) return [];
        return [this.tamperNextReload ? { ...record, ciphertext_hash: 'tampered' } : record];
      });
      this.tamperNextReload = false;
      return { data: rows as T, error: null };
    }
    if (fn === 'get_collection_author_trust_material') {
      return {
        data: [{
          user_id: ACTOR_USER_ID,
          vault_id: ACTOR_VAULT_ID,
          device_id: DEVICE_ID,
          public_signing_key: this.publicSigningKey,
          trust_epoch: 0,
          status: this.trustStatus,
        }] as T,
        error: null,
      };
    }
    if (fn === 'get_collection_head') {
      return {
        data: [{
          collection_id: COLLECTION_ID,
          current_head: this.currentHead,
          current_op_id: this.operations.at(-1)?.op_id ?? null,
          current_sequence_number: this.sequence,
          updated_at: '2026-05-08T00:00:00.000Z',
        }] as T,
        error: null,
      };
    }
    return { data: null, error: { code: '404', message: `unknown rpc ${fn}` } };
  }

  private submit(params: Record<string, unknown>): Record<string, unknown> {
    const op = params.p_op as Record<string, unknown>;
    const payload = params.p_record_payload as Record<string, unknown>;
    this.sequence += 1;
    const operation = {
      op_id: op.op_id,
      op_hash: op.op_hash,
      collection_id: op.collection_id,
      actor_user_id: ACTOR_USER_ID,
      actor_vault_id: op.actor_vault_id,
      author_device_id: op.author_device_id,
      op_type: op.op_type,
      record_id: op.record_id,
      record_type: op.record_type,
      base_record_version: op.base_record_version,
      previous_ciphertext_hash: op.previous_ciphertext_hash,
      new_record_hash: op.new_record_hash,
      base_collection_head: op.base_collection_head,
      resulting_collection_head: op.resulting_collection_head,
      payload_ciphertext_hash: op.payload_ciphertext_hash,
      payload_aad_hash: op.payload_aad_hash,
      signed_body: op.signed_body,
      signature: op.signature,
      signature_schema: op.signature_schema,
      trust_epoch: op.trust_epoch,
      created_at_client: op.created_at_client,
      received_at_server: '2026-05-08T00:00:00.000Z',
      sequence_number: this.sequence,
    };
    const existing = this.records.get(String(op.record_id));
    this.operations.push(this.tamperSignedBodyAfterSubmit
      ? { ...operation, signed_body: { ...(operation.signed_body as Record<string, unknown>), recordId: 'different-record-id' } }
      : operation);
    this.records.set(String(op.record_id), {
      collection_id: op.collection_id,
      record_id: op.record_id,
      record_type: op.record_type,
      record_version: existing ? Number(existing.record_version) + 1 : 1,
      key_version: payload.key_version,
      aad_hash: payload.aad_hash,
      ciphertext_hash: payload.ciphertext_hash,
      nonce: payload.nonce,
      ciphertext: payload.ciphertext,
      last_op_id: op.op_id,
      last_op_hash: op.op_hash,
      is_tombstone: op.op_type === 'delete' || op.op_type === 'remove_member',
      created_at: op.created_at_client,
      updated_at: op.created_at_client,
    });
    this.currentHead = String(op.resulting_collection_head);
    return {
      applied: true,
      idempotent: false,
      op_id: op.op_id,
      sequence_number: this.sequence,
      resulting_collection_head: op.resulting_collection_head,
      current_head: this.currentHead,
      current_sequence_number: this.sequence,
      conflict_reason: null,
    };
  }
}

async function deps(rpc: FakeCollectionRpcClient): Promise<CollectionOpLogCrudDependencies> {
  const keyPair = await generateDeviceSigningKeyPair();
  rpc.publicSigningKey = keyPair.publicKeyB64Url;
  return {
    collectionId: COLLECTION_ID,
    actorUserId: ACTOR_USER_ID,
    actorVaultId: ACTOR_VAULT_ID,
    authorDeviceId: DEVICE_ID,
    deviceSigningKey: keyPair.privateKey,
    collectionKey: crypto.getRandomValues(new Uint8Array(32)),
    trustEpoch: 0,
    keyVersion: 1,
    rpcClient: rpc,
  };
}

describe('collectionOpLogCrudService', () => {
  it('submits a signed collection metadata operation and verifies it after reload', async () => {
    const rpc = new FakeCollectionRpcClient();
    const dependencies = await deps(rpc);

    const state = await submitAndVerifyCollectionMutation(dependencies, {
      opType: 'create',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Family', description: null },
      base: null,
    });

    expect(rpc.operations).toHaveLength(1);
    expect(rpc.operations[0].signed_body).toMatchObject({
      collectionId: COLLECTION_ID,
      actorUserId: ACTOR_USER_ID,
      opType: 'create',
      recordType: 'collection_metadata',
    });
    expect(state.recordsById.get(COLLECTION_ID)?.state).toBe('verified');
  });

  it('blocks updates without verified collection base metadata', async () => {
    const dependencies = await deps(new FakeCollectionRpcClient());

    await expect(submitAndVerifyCollectionMutation(dependencies, {
      opType: 'update',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Renamed' },
      base: null,
    })).rejects.toBeInstanceOf(MissingCollectionBaseMetadataError);
  });

  it('fails UI success when committed operation is not verified after reload', async () => {
    const rpc = new FakeCollectionRpcClient();
    const dependencies = await deps(rpc);
    rpc.tamperNextReload = true;

    await expect(submitAndVerifyCollectionMutation(dependencies, {
      opType: 'create',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Family' },
      base: null,
    })).rejects.toBeInstanceOf(CollectionOperationNotVerifiedError);
  });

  it('does not decrypt or verify operations whose signed body does not match the operation row', async () => {
    const rpc = new FakeCollectionRpcClient();
    const dependencies = await deps(rpc);
    rpc.tamperSignedBodyAfterSubmit = true;

    await expect(submitAndVerifyCollectionMutation(dependencies, {
      opType: 'create',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Family' },
      base: null,
    })).rejects.toBeInstanceOf(CollectionOperationNotVerifiedError);
  });

  it('does not decrypt or verify operations from a revoked author device', async () => {
    const rpc = new FakeCollectionRpcClient();
    const dependencies = await deps(rpc);
    rpc.trustStatus = 'revoked';

    await expect(submitAndVerifyCollectionMutation(dependencies, {
      opType: 'create',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Family' },
      base: null,
    })).rejects.toBeInstanceOf(CollectionOperationNotVerifiedError);
  });

  it('derives verified base metadata from reloaded collection state', async () => {
    const rpc = new FakeCollectionRpcClient();
    const dependencies = await deps(rpc);
    const state = await submitAndVerifyCollectionMutation(dependencies, {
      opType: 'create',
      recordId: COLLECTION_ID,
      recordType: 'collection_metadata',
      plaintext: { name: 'Family' },
      base: null,
    });

    const base = await getVerifiedCollectionBase(dependencies, state, COLLECTION_ID);

    expect(base.recordVersion).toBe(1);
    expect(base.ciphertextHash).toBeTruthy();
    expect(base.baseCollectionHead).toBe(rpc.currentHead);
  });
});
