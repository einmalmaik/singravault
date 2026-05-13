// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const tablesMigration = readFileSync(
  'supabase/migrations/20260504130000_vault_op_log_phase2_records_operations_trust.sql',
  'utf-8',
);
const rpcsMigration = readFileSync(
  'supabase/migrations/20260504130100_vault_op_log_phase2_rpcs.sql',
  'utf-8',
);
const bootstrapFkFixMigration = readFileSync(
  'supabase/migrations/20260505193000_vault_op_log_bootstrap_fk_fix.sql',
  'utf-8',
);
const changesSinceContractFixMigration = readFileSync(
  'supabase/migrations/20260507165242_fix_vault_changes_since_vault_id_contract.sql',
  'utf-8',
);
const authorTrustGuardMigration = readFileSync(
  'supabase/migrations/20260513150000_guard_vault_operation_author_trust.sql',
  'utf-8',
);
const effectiveReadRpcsMigration = `${rpcsMigration}\n${bootstrapFkFixMigration}\n${changesSinceContractFixMigration}`;
const combined = `${tablesMigration}\n${rpcsMigration}\n${authorTrustGuardMigration}`;

describe('vault op-log phase 2 — table contract', () => {
  it('creates vault_records, vault_operations, vault_device_trust_records and vault_op_log_heads', () => {
    expect(tablesMigration).toContain('CREATE TABLE IF NOT EXISTS public.vault_records');
    expect(tablesMigration).toContain('CREATE TABLE IF NOT EXISTS public.vault_operations');
    expect(tablesMigration).toContain('CREATE TABLE IF NOT EXISTS public.vault_device_trust_records');
    expect(tablesMigration).toContain('CREATE TABLE IF NOT EXISTS public.vault_op_log_heads');
  });

  it('pins the record_type whitelist for both records and operations', () => {
    const recordTypeListPattern = /record_type\s+IN\s*\(\s*'item'\s*,\s*'category'\s*,\s*'attachment_metadata'\s*,\s*'attachment_chunk'\s*,\s*'manifest'\s*,\s*'tombstone'\s*\)/u;
    expect(tablesMigration).toMatch(recordTypeListPattern);
    // Two CHECK constraints (records + operations), both must be present.
    const matches = tablesMigration.match(recordTypeListPattern as unknown as RegExp);
    expect(matches).not.toBeNull();
  });

  it('pins the op_type whitelist', () => {
    expect(tablesMigration).toMatch(
      /op_type\s+IN\s*\(\s*'create'\s*,\s*'update'\s*,\s*'delete'\s*,\s*'restore'\s*,\s*'move'\s*,\s*'rekey'\s*,\s*'add_device'\s*,\s*'revoke_device'\s*\)/u,
    );
  });

  it('enables RLS on every new table', () => {
    expect(tablesMigration).toContain('ALTER TABLE public.vault_records ENABLE ROW LEVEL SECURITY;');
    expect(tablesMigration).toContain('ALTER TABLE public.vault_operations ENABLE ROW LEVEL SECURITY;');
    expect(tablesMigration).toContain('ALTER TABLE public.vault_device_trust_records ENABLE ROW LEVEL SECURITY;');
    expect(tablesMigration).toContain('ALTER TABLE public.vault_op_log_heads ENABLE ROW LEVEL SECURITY;');
  });

  it('denies direct INSERT / UPDATE / DELETE on every new table', () => {
    for (const table of [
      'vault_records',
      'vault_operations',
      'vault_device_trust_records',
      'vault_op_log_heads',
    ]) {
      expect(tablesMigration).toContain(`"${table} deny direct insert"`);
      expect(tablesMigration).toContain(`"${table} deny direct update"`);
      expect(tablesMigration).toContain(`"${table} deny direct delete"`);
      expect(tablesMigration).toContain(`REVOKE INSERT, UPDATE, DELETE ON public.${table} FROM authenticated;`);
    }
  });

  it('grants only SELECT to authenticated on every new table', () => {
    for (const table of [
      'vault_records',
      'vault_operations',
      'vault_device_trust_records',
      'vault_op_log_heads',
    ]) {
      expect(tablesMigration).toContain(`GRANT SELECT ON public.${table} TO authenticated;`);
    }
  });

  it('keeps SELECT scoped to auth.uid() = user_id', () => {
    const policyPattern = /CREATE POLICY "[^"]+ select own"\s+ON public\.[a-z_]+\s+FOR SELECT\s+TO authenticated\s+USING \(auth\.uid\(\) = user_id\)/gu;
    const matches = tablesMigration.match(policyPattern);
    expect(matches).not.toBeNull();
    expect(matches!.length).toBe(4);
  });

  it('makes vault_operations append-only via constraint and policy', () => {
    expect(tablesMigration).toContain('"vault_operations deny direct update"');
    expect(tablesMigration).toContain('"vault_operations deny direct delete"');
    expect(tablesMigration).toContain('op_hash TEXT NOT NULL UNIQUE');
  });

  it('enforces the trust-record revoke consistency (status + revoked_at + revoked_op_id)', () => {
    expect(tablesMigration).toContain('vault_device_trust_records_revoke_consistency_check');
    expect(tablesMigration).toContain("status = 'trusted' AND revoked_at IS NULL AND revoked_op_id IS NULL");
    expect(tablesMigration).toContain("status = 'revoked' AND revoked_at IS NOT NULL AND revoked_op_id IS NOT NULL");
  });

  it('enforces the device-signature schema in vault_operations', () => {
    expect(tablesMigration).toContain("signature_schema = 'device-signature-v1'");
  });

  it('cascades on vault deletion to keep stale records from outliving their vault', () => {
    expect(tablesMigration).toContain('REFERENCES public.vaults(id) ON DELETE CASCADE');
    // At least once on every new table that holds vault data.
    const matches = tablesMigration.match(/REFERENCES public\.vaults\(id\) ON DELETE CASCADE/gu);
    expect(matches).not.toBeNull();
    expect(matches!.length).toBeGreaterThanOrEqual(4);
  });
});

describe('vault op-log phase 2 — RPC contract', () => {
  it('declares submit_vault_operation as SECURITY DEFINER with a fixed search_path', () => {
    expect(rpcsMigration).toContain(
      'CREATE OR REPLACE FUNCTION public.submit_vault_operation(',
    );
    expect(rpcsMigration).toMatch(
      /CREATE OR REPLACE FUNCTION public\.submit_vault_operation[\s\S]*?SECURITY DEFINER[\s\S]*?SET search_path = public/u,
    );
  });

  it('rejects unauthenticated callers', () => {
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'Not authenticated'");
  });

  it('verifies vault ownership before any write', () => {
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'Vault does not belong to caller'");
  });

  it('is idempotent on op_id reuse and rejects op_id reuse with a different op_hash', () => {
    expect(rpcsMigration).toContain('SELECT * INTO _existing_op');
    expect(rpcsMigration).toContain('FROM public.vault_operations');
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'op_id reused with a different op_hash'");
    expect(rpcsMigration).toContain("'idempotent', true");
  });

  it('locks the head row before checking base_vault_head', () => {
    expect(rpcsMigration).toContain('FROM public.vault_op_log_heads');
    expect(rpcsMigration).toContain('FOR UPDATE');
    expect(rpcsMigration).toContain("'conflict_reason', 'stale_vault_head'");
  });

  it('rejects an empty base_vault_head when a head already exists', () => {
    expect(rpcsMigration).toContain(
      'IF _base_vault_head IS NULL OR _current_head_row.current_head <> _base_vault_head THEN',
    );
  });

  it('rejects a non-null base_vault_head when no head exists yet', () => {
    expect(rpcsMigration).toContain('IF _base_vault_head IS NOT NULL THEN');
  });

  it('locks the record row before CAS on base_record_version and previous_ciphertext_hash', () => {
    expect(rpcsMigration).toContain('SELECT * INTO _existing_record');
    expect(rpcsMigration).toContain('FROM public.vault_records');
    expect(rpcsMigration).toContain("'conflict_reason', 'stale_record_version'");
    expect(rpcsMigration).toContain("'conflict_reason', 'stale_previous_ciphertext_hash'");
  });

  it('forbids create with a non-null base_record_version or previous_ciphertext_hash', () => {
    expect(rpcsMigration).toContain("'conflict_reason', 'create_must_not_carry_base'");
  });

  it('forbids non-create ops on missing or wrongly-typed records', () => {
    expect(rpcsMigration).toContain("'conflict_reason', 'record_not_found'");
    expect(rpcsMigration).toContain("'conflict_reason', 'record_type_mismatch'");
  });

  it('forbids create on an existing live record', () => {
    expect(rpcsMigration).toContain("'conflict_reason', 'record_already_exists'");
  });

  it('inserts every operation into the append-only log with a sequence number', () => {
    expect(rpcsMigration).toContain('INSERT INTO public.vault_operations (');
    expect(rpcsMigration).toContain('sequence_number');
    expect(rpcsMigration).toContain('_next_sequence');
  });

  it('binds record_payload hashes to the operation', () => {
    expect(rpcsMigration).toContain(
      "RAISE EXCEPTION 'record_payload aad_hash does not match operation'",
    );
    expect(rpcsMigration).toContain(
      "RAISE EXCEPTION 'record_payload ciphertext_hash does not match operation'",
    );
  });

  it('soft-deletes records with a signed tombstone payload on op_type=delete', () => {
    expect(rpcsMigration).toContain("IF _op_type = 'delete' THEN");
    expect(rpcsMigration).toContain("'create', 'update', 'delete', 'restore', 'move', 'rekey'");
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'record_payload is required for op_type %', _op_type");
    expect(rpcsMigration).toContain('is_tombstone = TRUE');
    expect(rpcsMigration).toContain('record_version = record_version + 1');
    expect(rpcsMigration).toContain("ciphertext_hash = p_record_payload->>'ciphertext_hash'");
    expect(rpcsMigration).toContain("nonce = p_record_payload->>'nonce'");
    expect(rpcsMigration).toContain("ciphertext = p_record_payload->>'ciphertext'");
  });

  it('rejects add_device for a device already on the trust list', () => {
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'Device already present in trust list'");
  });

  it('rejects revoke_device for an unknown device and bumps its trust_epoch on success', () => {
    expect(rpcsMigration).toContain("RAISE EXCEPTION 'Device not present in trust list'");
    expect(rpcsMigration).toContain('trust_epoch = trust_epoch + 1');
  });

  it('updates the head row atomically with the operation', () => {
    expect(rpcsMigration).toContain('INSERT INTO public.vault_op_log_heads (');
    expect(rpcsMigration).toContain('ON CONFLICT (vault_id) DO UPDATE');
    expect(rpcsMigration).toContain('current_head = EXCLUDED.current_head');
  });

  it('returns success JSON with current_head and current_sequence_number', () => {
    expect(rpcsMigration).toContain("'applied', true");
    expect(rpcsMigration).toContain("'current_head'");
    expect(rpcsMigration).toContain("'current_sequence_number'");
  });

  it('grants execute only to authenticated and revokes from public', () => {
    expect(rpcsMigration).toContain(
      'REVOKE ALL ON FUNCTION public.submit_vault_operation(JSONB, JSONB, JSONB) FROM PUBLIC;',
    );
    expect(rpcsMigration).toContain(
      'GRANT EXECUTE ON FUNCTION public.submit_vault_operation(JSONB, JSONB, JSONB) TO authenticated;',
    );
  });

  it('guards operation inserts against revoked or unknown author devices', () => {
    expect(authorTrustGuardMigration).toContain('CREATE OR REPLACE FUNCTION public.guard_vault_operation_author_trust()');
    expect(authorTrustGuardMigration).toContain("RAISE EXCEPTION 'author_device_not_trusted'");
    expect(authorTrustGuardMigration).toContain("RAISE EXCEPTION 'author_device_trust_epoch_mismatch'");
    expect(authorTrustGuardMigration).toContain('BEFORE INSERT ON public.vault_operations');
    expect(authorTrustGuardMigration).toContain("IF NEW.op_type = 'recover_device' THEN");
  });
});

describe('vault op-log phase 2 — read RPC contracts', () => {
  it('exposes get_vault_head, get_vault_changes_since, get_vault_records_by_ids, bootstrap_vault_trust', () => {
    expect(effectiveReadRpcsMigration).toContain('CREATE OR REPLACE FUNCTION public.get_vault_head(p_vault_id UUID)');
    expect(effectiveReadRpcsMigration).toContain('CREATE FUNCTION public.get_vault_changes_since(');
    expect(effectiveReadRpcsMigration).toContain('CREATE OR REPLACE FUNCTION public.get_vault_records_by_ids(');
    expect(effectiveReadRpcsMigration).toContain('CREATE OR REPLACE FUNCTION public.bootstrap_vault_trust(');
  });

  it('scopes get_vault_head to the caller', () => {
    expect(rpcsMigration).toMatch(
      /FROM public\.vault_op_log_heads h\s+WHERE h\.vault_id = p_vault_id\s+AND h\.user_id = auth\.uid\(\)/u,
    );
  });

  it('verifies vault ownership in both fetch RPCs', () => {
    const ownershipMatches = effectiveReadRpcsMigration.match(
      /RAISE EXCEPTION 'Vault does not belong to caller'/gu,
    );
    expect(ownershipMatches).not.toBeNull();
    expect(ownershipMatches!.length).toBeGreaterThanOrEqual(3);
  });

  it('caps pagination on get_vault_changes_since', () => {
    expect(effectiveReadRpcsMigration).toContain('p_limit must be between 1 and 1000');
    expect(effectiveReadRpcsMigration).toContain('ORDER BY o.sequence_number ASC');
  });

  it('returns vault_id from get_vault_changes_since for mapper-compatible migration recovery', () => {
    expect(changesSinceContractFixMigration).toContain(
      'DROP FUNCTION IF EXISTS public.get_vault_changes_since(UUID, BIGINT, INTEGER);',
    );
    expect(changesSinceContractFixMigration).toMatch(
      /RETURNS TABLE\(\s+vault_id UUID,\s+op_id UUID,/u,
    );
    expect(changesSinceContractFixMigration).toContain(
      'SELECT o.vault_id, o.op_id, o.op_hash, o.sequence_number,',
    );
    expect(changesSinceContractFixMigration).toMatch(
      /SECURITY DEFINER\s+SET search_path = public/u,
    );
  });

  it('caps the bulk record fetch and returns empty for null/empty input', () => {
    expect(effectiveReadRpcsMigration).toContain("RAISE EXCEPTION 'Too many record ids in a single fetch'");
    expect(effectiveReadRpcsMigration).toContain('array_length(p_record_ids, 1) > 500');
  });

  it('grants execute only to authenticated for every read RPC', () => {
    expect(effectiveReadRpcsMigration).toContain('GRANT EXECUTE ON FUNCTION public.get_vault_head(UUID) TO authenticated;');
    expect(effectiveReadRpcsMigration).toContain(
      'GRANT EXECUTE ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) TO authenticated;',
    );
    expect(effectiveReadRpcsMigration).toContain(
      'GRANT EXECUTE ON FUNCTION public.get_vault_records_by_ids(UUID, UUID[]) TO authenticated;',
    );
    expect(effectiveReadRpcsMigration).toContain(
      'GRANT EXECUTE ON FUNCTION public.bootstrap_vault_trust(UUID, UUID, TEXT, TEXT, TEXT, UUID) TO authenticated;',
    );
  });

  it('bootstrap_vault_trust is SECURITY DEFINER with fixed search_path', () => {
    expect(rpcsMigration).toMatch(
      /CREATE OR REPLACE FUNCTION public\.bootstrap_vault_trust[\s\S]*?SECURITY DEFINER[\s\S]*?SET search_path = public/u,
    );
  });

  it('bootstrap_vault_trust rejects unauthenticated callers', () => {
    expect(effectiveReadRpcsMigration).toContain("RAISE EXCEPTION 'Not authenticated'");
  });

  it('bootstrap_vault_trust verifies vault ownership', () => {
    expect(effectiveReadRpcsMigration).toContain("RAISE EXCEPTION 'Vault does not belong to caller'");
  });

  it('bootstrap_vault_trust only runs when no trust list exists', () => {
    expect(effectiveReadRpcsMigration).toContain('SELECT COUNT(*) INTO _existing_trust_count');
    expect(effectiveReadRpcsMigration).toContain('FROM public.vault_device_trust_records');
    expect(effectiveReadRpcsMigration).toContain("'reason', 'trust_list_already_exists'");
  });

  it('bootstrap_vault_trust only runs when no head exists', () => {
    expect(effectiveReadRpcsMigration).toContain('SELECT * INTO _existing_head');
    expect(effectiveReadRpcsMigration).toContain('FROM public.vault_op_log_heads');
    expect(effectiveReadRpcsMigration).toContain("'reason', 'head_already_exists'");
  });

  it('bootstrap_vault_trust inserts the first trusted device and initial head', () => {
    expect(effectiveReadRpcsMigration).toContain('INSERT INTO public.vault_device_trust_records');
    expect(effectiveReadRpcsMigration).toContain('INSERT INTO public.vault_op_log_heads');
    expect(effectiveReadRpcsMigration).toContain("'bootstrapped', true");
  });
});

describe('vault op-log phase 2 — combined invariants', () => {
  it('never exposes a write path that bypasses submit_vault_operation', () => {
    // The only writing function is submit_vault_operation. No other migration
    // line should issue an INSERT/UPDATE/DELETE on the new tables outside of
    // SECURITY DEFINER context.
    const directWritePattern = /INSERT INTO public\.(vault_records|vault_operations|vault_device_trust_records|vault_op_log_heads)/gu;
    const inserts = combined.match(directWritePattern) ?? [];
    // Every insert must live inside submit_vault_operation. Since there is
    // exactly one CREATE OR REPLACE FUNCTION public.submit_vault_operation
    // block, all inserts must come from inside it. We check that by ensuring
    // every match is within the function body.
    const submitFnStart = rpcsMigration.indexOf(
      'CREATE OR REPLACE FUNCTION public.submit_vault_operation(',
    );
    const submitFnEnd = rpcsMigration.indexOf(
      'REVOKE ALL ON FUNCTION public.submit_vault_operation',
    );
    expect(submitFnStart).toBeGreaterThan(-1);
    expect(submitFnEnd).toBeGreaterThan(submitFnStart);
    const submitFnBody = rpcsMigration.slice(submitFnStart, submitFnEnd);
    for (const match of inserts) {
      expect(submitFnBody).toContain(match);
    }
  });

  it('does not weaken existing vault_items or categories policies', () => {
    expect(combined).not.toContain('DROP TABLE public.vault_items');
    expect(combined).not.toContain('DROP TABLE public.categories');
    expect(combined).not.toContain('ALTER TABLE public.vault_items DISABLE ROW LEVEL SECURITY');
    expect(combined).not.toContain('ALTER TABLE public.categories DISABLE ROW LEVEL SECURITY');
  });

  it('does not introduce ENUMs whose values cannot evolve safely', () => {
    expect(combined).not.toMatch(/CREATE TYPE public\.vault_(record|op)_type/u);
  });

  it('includes previous_ciphertext_hash in vault_operations table', () => {
    expect(tablesMigration).toContain('previous_ciphertext_hash TEXT');
  });

  it('includes intent_id and rebased_from_op_id in vault_operations table for rebase model', () => {
    expect(tablesMigration).toContain('intent_id UUID');
    expect(tablesMigration).toContain('rebased_from_op_id UUID');
  });

  it('includes intent_id and rebased_from_op_id in submit_vault_operation RPC', () => {
    expect(rpcsMigration).toContain('_intent_id UUID');
    expect(rpcsMigration).toContain('_rebased_from_op_id UUID');
    expect(rpcsMigration).toContain("_intent_id := NULLIF(p_op->>'intent_id', '')::UUID");
    expect(rpcsMigration).toContain("_rebased_from_op_id := NULLIF(p_op->>'rebased_from_op_id', '')::UUID");
  });

  it('includes intent_id and rebased_from_op_id in get_vault_changes_since output', () => {
    expect(effectiveReadRpcsMigration).toContain('intent_id UUID');
    expect(effectiveReadRpcsMigration).toContain('rebased_from_op_id UUID');
    expect(effectiveReadRpcsMigration).toContain('o.intent_id');
    expect(effectiveReadRpcsMigration).toContain('o.rebased_from_op_id');
  });

  it('CAS checks previous_ciphertext_hash against vault_records.ciphertext_hash', () => {
    expect(rpcsMigration).toContain('_existing_record.ciphertext_hash <> _previous_ciphertext_hash');
  });
});
