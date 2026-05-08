// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const sql = readFileSync('supabase/migrations/20260508142024_collection_op_log.sql', 'utf8');

describe('collection op log SQL contract', () => {
  it('creates signed collection operation tables with direct writes denied', () => {
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS public.collection_records');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS public.collection_operations');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS public.collection_op_log_heads');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS public.collection_op_log_key_envelopes');
    expect(sql).toContain('ALTER TABLE public.collection_records ENABLE ROW LEVEL SECURITY');
    expect(sql).toContain('ALTER TABLE public.collection_op_log_key_envelopes ENABLE ROW LEVEL SECURITY');
    expect(sql).toContain('REVOKE INSERT, UPDATE, DELETE ON public.collection_records FROM authenticated');
    expect(sql).toContain('REVOKE INSERT, UPDATE, DELETE ON public.collection_operations FROM authenticated');
    expect(sql).toContain('REVOKE INSERT, UPDATE, DELETE ON public.collection_op_log_key_envelopes FROM authenticated');
  });

  it('exposes only SECURITY DEFINER RPC write/read paths with fixed search_path', () => {
    expect(sql).toContain('CREATE OR REPLACE FUNCTION public.submit_collection_operation');
    expect(sql).toContain('SECURITY DEFINER');
    expect(sql).toContain('SET search_path = public');
    expect(sql).toContain('REVOKE ALL ON FUNCTION public.is_collection_op_log_active_member(UUID, UUID) FROM PUBLIC');
    expect(sql).toContain('GRANT EXECUTE ON FUNCTION public.submit_collection_operation(JSONB, JSONB, JSONB) TO authenticated');
    expect(sql).toContain('GRANT EXECUTE ON FUNCTION public.get_collection_changes_since(UUID, BIGINT, INTEGER) TO authenticated');
    expect(sql).toContain('GRANT EXECUTE ON FUNCTION public.get_collection_key_envelope(UUID) TO authenticated');
  });

  it('enforces collection head and record CAS conflict responses', () => {
    expect(sql).toContain("'stale_collection_head'");
    expect(sql).toContain("'stale_record_version'");
    expect(sql).toContain("'stale_previous_ciphertext_hash'");
    expect(sql).toContain('op_id reused with a different op_hash');
  });
});
