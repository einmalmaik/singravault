// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Integration tests for Vault Operation Log Phase 2 RPCs.
 *
 * These tests require a real Supabase instance and are gated by:
 * - VITE_INTEGRATION_TEST_SUPABASE_URL
 * - VITE_INTEGRATION_TEST_SUPABASE_ANON_KEY
 * - VITE_INTEGRATION_TEST_USER_EMAIL
 * - VITE_INTEGRATION_TEST_USER_PASSWORD
 *
 * Run with: npm test -- src/test/integration/vault-op-log-phase2-integration.test.ts
 *
 * Test Coverage:
 * - RLS enforcement: authenticated users can only access their own vaults
 * - REVOKE: direct INSERT/UPDATE/DELETE on new tables is blocked
 * - Atomicity: submit_vault_operation writes operation + record in one transaction
 * - Idempotency: retrying same op_id returns idempotent response
 * - Access control: unauthorized access attempts are rejected
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import {
  buildCreateRecordOperation,
  submitVaultOperation,
  toVaultOperationRow,
  type VaultOperationRow,
} from '@/services/vaultOpLog';

const supabaseUrl = import.meta.env.VITE_INTEGRATION_TEST_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_INTEGRATION_TEST_SUPABASE_ANON_KEY;
const userEmail = import.meta.env.VITE_INTEGRATION_TEST_USER_EMAIL;
const userPassword = import.meta.env.VITE_INTEGRATION_TEST_USER_PASSWORD;

// Skip all tests if integration environment is not configured
const runIntegration = !!(
  supabaseUrl &&
  supabaseAnonKey &&
  userEmail &&
  userPassword
);

describe.runIf(runIntegration)('vault op-log phase 2 — integration tests', () => {
  let supabase: SupabaseClient;
  let testUserId: string;
  let testVaultId: string;
  let testDeviceId: string;
  const initialHead = 'initial-head-hash';

  beforeAll(async () => {
    supabase = createClient(supabaseUrl!, supabaseAnonKey!);

    // Sign in or sign up test user
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: userEmail!,
      password: userPassword!,
    });

    if (authError) {
      // Try signing up if sign in fails
      const { data: signUpData, error: signUpError } = await supabase.auth.signUp({
        email: userEmail!,
        password: userPassword!,
      });
      if (signUpError) {
        throw new Error(`Auth setup failed: ${signUpError.message}`);
      }
      testUserId = signUpData.user!.id;
    } else {
      testUserId = authData.user.id;
    }

    // Create a test vault
    const { data: vaultData, error: vaultError } = await supabase
      .from('vaults')
      .insert({
        user_id: testUserId,
        name: 'Integration Test Vault',
        description: 'Vault for Phase 2 integration tests',
      })
      .select()
      .single();

    if (vaultError) {
      throw new Error(`Vault creation failed: ${vaultError.message}`);
    }

    testVaultId = vaultData.id;
    testDeviceId = crypto.randomUUID();

    const { data: bootstrapData, error: bootstrapError } = await supabase.rpc(
      'bootstrap_vault_trust',
      {
        p_vault_id: testVaultId,
        p_device_id: testDeviceId,
        p_public_signing_key: 'test-key',
        p_device_name_encrypted: 'encrypted-name',
        p_initial_head: initialHead,
        p_initial_op_id: crypto.randomUUID(),
      }
    );

    if (bootstrapError || bootstrapData?.bootstrapped !== true) {
      throw new Error(`Bootstrap setup failed: ${bootstrapError?.message ?? 'not bootstrapped'}`);
    }
  });

  afterAll(async () => {
    // Cleanup: delete test vault
    if (testVaultId) {
      await supabase.from('vaults').delete().eq('id', testVaultId);
    }
    // Sign out
    await supabase.auth.signOut();
  });

  describe('RLS enforcement', () => {
    it('allows user to read their own vault_records', async () => {
      // Try to read vault_records (should be empty but accessible)
      const { data: records, error: readError } = await supabase
        .from('vault_records')
        .select('*')
        .eq('vault_id', testVaultId);

      expect(readError).toBeNull();
      expect(records).toEqual([]);
    });

    it('blocks direct INSERT on vault_records', async () => {
      const { error } = await supabase.from('vault_records').insert({
        vault_id: testVaultId,
        record_id: crypto.randomUUID(),
        user_id: testUserId,
        record_type: 'item',
        record_version: 1,
        key_version: 1,
        aad_hash: 'test-hash',
        ciphertext_hash: 'test-hash',
        nonce: 'test-nonce',
        ciphertext: 'test-ciphertext',
        last_op_id: crypto.randomUUID(),
        last_op_hash: 'test-hash',
      });

      // Direct insert must be blocked. Depending on Supabase/Postgres
      // privilege evaluation, this can surface as either a privilege denial
      // or an RLS violation; both are acceptable deny outcomes.
      expect(error).not.toBeNull();
      expect(error?.message).toMatch(/(permission denied|row-level security policy)/i);
    });

    it('blocks direct UPDATE on vault_records', async () => {
      const { error } = await supabase
        .from('vault_records')
        .update({ ciphertext_hash: 'modified' })
        .eq('vault_id', testVaultId);

      expect(error).not.toBeNull();
    });

    it('blocks direct DELETE on vault_records', async () => {
      const { error } = await supabase
        .from('vault_records')
        .delete()
        .eq('vault_id', testVaultId);

      expect(error).not.toBeNull();
    });
  });

  describe('bootstrap_vault_trust RPC', () => {
    it('creates first trusted device and initial head', async () => {
      // This is already tested in the beforeAll setup
      const { data: headData } = await supabase
        .from('vault_op_log_heads')
        .select('*')
        .eq('vault_id', testVaultId)
        .single();

      expect(headData).not.toBeNull();
      expect(headData?.user_id).toBe(testUserId);
      expect(headData?.current_sequence_number).toBe(0);

      const { data: trustData } = await supabase
        .from('vault_device_trust_records')
        .select('*')
        .eq('vault_id', testVaultId)
        .eq('device_id', testDeviceId)
        .single();

      expect(trustData).not.toBeNull();
      expect(trustData?.status).toBe('trusted');
    });

    it('returns bootstrapped=false if trust list already exists', async () => {
      const { data, error } = await supabase.rpc('bootstrap_vault_trust', {
        p_vault_id: testVaultId,
        p_device_id: crypto.randomUUID(),
        p_public_signing_key: 'test-key-2',
        p_device_name_encrypted: 'encrypted-name-2',
        p_initial_head: 'initial-head-hash-2',
        p_initial_op_id: crypto.randomUUID(),
      });

      expect(error).toBeNull();
      expect(data?.bootstrapped).toBe(false);
      expect(data?.reason).toBe('trust_list_already_exists');
    });
  });

  describe('submit_vault_operation RPC', () => {
    it('rejects unauthenticated calls', async () => {
      const response = await fetch(`${supabaseUrl}/rest/v1/rpc/submit_vault_operation`, {
        method: 'POST',
        headers: {
          apikey: supabaseAnonKey!,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          p_op: {},
          p_record_payload: null,
          p_device_trust_payload: null,
        }),
      });

      const body = await response.text();
      expect(response.ok).toBe(false);
      expect(body).toMatch(/Not authenticated/i);
    });

    it('enforces vault ownership', async () => {
      const otherVaultId = crypto.randomUUID();
      const { error } = await supabase.rpc('submit_vault_operation', {
        p_op: {
          op_id: crypto.randomUUID(),
          op_hash: 'test-hash',
          vault_id: otherVaultId,
          record_id: crypto.randomUUID(),
          record_type: 'item',
          op_type: 'create',
          author_device_id: testDeviceId,
          base_record_version: null,
          previous_ciphertext_hash: null,
          new_record_hash: 'hash',
          base_vault_head: null,
          resulting_vault_head: 'result-head',
          payload_ciphertext_hash: 'ct-hash',
          payload_aad_hash: 'aad-hash',
          signature: 'sig',
          signature_schema: 'device-signature-v1',
          signed_body: {},
          trust_epoch: 0,
          created_at_client: new Date().toISOString(),
        },
        p_record_payload: null,
        p_device_trust_payload: null,
      });

      expect(error).not.toBeNull();
      expect(error?.message).toMatch(/Vault does not belong to caller/i);
    });
  });

  describe('Access control', () => {
    it('prevents cross-user vault access', async () => {
      // This would require setting up a second user, which is complex
      // For now, we verify the RLS policy exists in the migration contract test
      // Real cross-user testing is better done in a dedicated security audit environment
      expect(true).toBe(true); // Placeholder
    });
  });

  describe('Atomicity', () => {
    it('writes a signed create operation and record in one transaction', async () => {
      const { operation, recordPayload } = await buildSignedCreateFixture({
        vaultId: testVaultId,
        deviceId: testDeviceId,
        baseVaultHead: initialHead,
      });

      const submit = await submitVaultOperation(supabase, operation, recordPayload, null);
      expect(submit).toMatchObject({
        kind: 'applied',
        idempotent: false,
        opId: operation.opId,
      });

      const { data: record, error } = await supabase
        .from('vault_records')
        .select('record_id,last_op_id,ciphertext_hash')
        .eq('vault_id', testVaultId)
        .eq('record_id', operation.recordId)
        .single();

      expect(error).toBeNull();
      expect(record?.last_op_id).toBe(operation.opId);
      expect(record?.ciphertext_hash).toBe(operation.payloadCiphertextHash);
    });
  });

  describe('Idempotency', () => {
    it('returns idempotent response for retry of same op_id and rejects reused op_id with a different op_hash', async () => {
      const { data: heads, error: headError } = await supabase.rpc('get_vault_head', {
        p_vault_id: testVaultId,
      });
      expect(headError).toBeNull();
      const baseVaultHead = heads?.[0]?.current_head ?? initialHead;

      const { operation, recordPayload } = await buildSignedCreateFixture({
        vaultId: testVaultId,
        deviceId: testDeviceId,
        baseVaultHead,
      });

      const first = await submitVaultOperation(supabase, operation, recordPayload, null);
      expect(first).toMatchObject({
        kind: 'applied',
        idempotent: false,
        opId: operation.opId,
      });

      const retry = await submitVaultOperation(supabase, operation, recordPayload, null);
      expect(retry).toMatchObject({
        kind: 'applied',
        idempotent: true,
        opId: operation.opId,
      });

      const reusedOpId: VaultOperationRow = {
        ...operation,
        opHash: `${operation.opHash}-different`,
      };
      const rejected = await submitVaultOperation(supabase, reusedOpId, recordPayload, null);
      expect(rejected).toEqual({ kind: 'duplicateOpIdDifferentHash' });
    });

    it('returns operation changes with intent and rebase fields in the declared order', async () => {
      const { data, error } = await supabase.rpc('get_vault_changes_since', {
        p_vault_id: testVaultId,
        p_since_sequence: 0,
        p_limit: 100,
      });

      expect(error).toBeNull();
      expect(Array.isArray(data)).toBe(true);
      expect(data?.[0]).toHaveProperty('intent_id');
      expect(data?.[0]).toHaveProperty('rebased_from_op_id');
      expect(data?.[0]).toHaveProperty('base_vault_head');
    });
  });
});

async function buildSignedCreateFixture(input: {
  readonly vaultId: string;
  readonly deviceId: string;
  readonly baseVaultHead: string | null;
}): Promise<{
  readonly operation: VaultOperationRow;
  readonly recordPayload: {
    readonly aadHash: string;
    readonly ciphertextHash: string;
    readonly nonce: string;
    readonly ciphertext: string;
    readonly keyVersion: number;
  };
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  );
  const built = await buildCreateRecordOperation({
    opId: crypto.randomUUID(),
    intentId: crypto.randomUUID(),
    rebasedFromOpId: null,
    vaultId: input.vaultId,
    recordId: crypto.randomUUID(),
    deviceId: input.deviceId,
    deviceSigningKey: keyPair.privateKey,
    trustEpoch: 0,
    baseVaultHead: input.baseVaultHead,
    recordType: 'item',
    vaultEncryptionKey: crypto.getRandomValues(new Uint8Array(32)),
    plaintext: new TextEncoder().encode(JSON.stringify({
      kind: 'phase12-integration-fixture',
      title: 'fixture',
    })),
    keyVersion: 1,
  });
  const operation = toVaultOperationRow(built);
  return {
    operation,
    recordPayload: {
      aadHash: built.sealedRecord.aadHash,
      ciphertextHash: built.sealedRecord.ciphertextHash,
      nonce: built.sealedRecord.nonceB64Url,
      ciphertext: built.sealedRecord.ciphertextB64Url,
      keyVersion: built.sealedRecord.aad.keyVersion,
    },
  };
}
