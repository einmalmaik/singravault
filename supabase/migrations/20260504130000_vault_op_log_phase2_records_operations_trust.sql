-- ===========================================================================
-- Vault Operation Log — Phase 2 (server-side schema + RPCs)
-- ---------------------------------------------------------------------------
-- See:
--   docs/adr/0004-vault-operation-log-and-record-integrity.md
--   docs/vault-op-log/inventory-and-phase-plan.md
--   src/services/vaultOpLog/
--
-- This migration creates the operation-log substrate that will replace
-- direct vault_items / categories writes and the V2 manifest in phases 6 / 7.
--
-- IMPORTANT INVARIANTS (binding):
--   1. Every mutation goes through public.submit_vault_operation. RLS denies
--      direct INSERT / UPDATE / DELETE on the new tables for authenticated
--      users. Only the SECURITY DEFINER RPC may write.
--   2. The server is NOT a trust source. It enforces structural CAS only:
--      base_record_version, base_vault_head, previous_ciphertext_hash, op_id
--      uniqueness. Signature and AAD verification stay client-side.
--   3. Rebase model: intent_id + rebased_from_op_id allow clients to
--      retry operations with a fresh base_vault_head while preserving
--      intent identity. The server stores but does not interpret these fields.
--   3. Operations are append-only. There is no UPDATE or DELETE path on
--      public.vault_operations.
--   4. The new tables coexist with vault_items / categories / vault_sync_heads.
--      Phase 6 wires the runtime onto the new tables; phase 7 removes the
--      legacy paths.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 1. vault_records — one row per logical record (item, category, ...).
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.vault_records (
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    record_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL,
    record_version BIGINT NOT NULL CHECK (record_version >= 0),
    key_version BIGINT NOT NULL CHECK (key_version >= 0),
    aad_hash TEXT NOT NULL,
    ciphertext_hash TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    last_op_id UUID NOT NULL,
    last_op_hash TEXT NOT NULL,
    is_tombstone BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, record_id),
    CONSTRAINT vault_records_record_type_check CHECK (
        record_type IN (
            'item',
            'category',
            'attachment_metadata',
            'attachment_chunk',
            'manifest',
            'tombstone'
        )
    )
);

CREATE INDEX IF NOT EXISTS vault_records_user_id_idx
    ON public.vault_records(user_id);

CREATE INDEX IF NOT EXISTS vault_records_vault_record_type_idx
    ON public.vault_records(vault_id, record_type);

CREATE INDEX IF NOT EXISTS vault_records_updated_at_idx
    ON public.vault_records(vault_id, updated_at);

ALTER TABLE public.vault_records ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vault_records select own" ON public.vault_records;
CREATE POLICY "vault_records select own"
    ON public.vault_records
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- INSERT / UPDATE / DELETE intentionally have no permissive policy.
-- All writes go through public.submit_vault_operation (SECURITY DEFINER).
DROP POLICY IF EXISTS "vault_records deny direct insert" ON public.vault_records;
CREATE POLICY "vault_records deny direct insert"
    ON public.vault_records
    FOR INSERT
    TO authenticated
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_records deny direct update" ON public.vault_records;
CREATE POLICY "vault_records deny direct update"
    ON public.vault_records
    FOR UPDATE
    TO authenticated
    USING (false)
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_records deny direct delete" ON public.vault_records;
CREATE POLICY "vault_records deny direct delete"
    ON public.vault_records
    FOR DELETE
    TO authenticated
    USING (false);

REVOKE INSERT, UPDATE, DELETE ON public.vault_records FROM authenticated;
GRANT SELECT ON public.vault_records TO authenticated;

-- ---------------------------------------------------------------------------
-- 2. vault_operations — append-only signed operation log.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.vault_operations (
    op_id UUID PRIMARY KEY,
    op_hash TEXT NOT NULL UNIQUE,
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    author_device_id UUID NOT NULL,
    op_type TEXT NOT NULL,
    record_id UUID NOT NULL,
    record_type TEXT NOT NULL,
    base_record_version BIGINT,
    previous_ciphertext_hash TEXT,
    new_record_hash TEXT,
    base_vault_head TEXT,
    resulting_vault_head TEXT NOT NULL,
    intent_id UUID,
    rebased_from_op_id UUID,
    payload_ciphertext_hash TEXT,
    payload_aad_hash TEXT,
    signed_body JSONB NOT NULL,
    signature TEXT NOT NULL,
    signature_schema TEXT NOT NULL,
    trust_epoch BIGINT NOT NULL CHECK (trust_epoch >= 0),
    created_at_client TIMESTAMPTZ NOT NULL,
    received_at_server TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sequence_number BIGINT NOT NULL,
    CONSTRAINT vault_operations_op_type_check CHECK (
        op_type IN (
            'create',
            'update',
            'delete',
            'restore',
            'move',
            'rekey',
            'add_device',
            'revoke_device'
        )
    ),
    CONSTRAINT vault_operations_record_type_check CHECK (
        record_type IN (
            'item',
            'category',
            'attachment_metadata',
            'attachment_chunk',
            'manifest',
            'tombstone'
        )
    ),
    CONSTRAINT vault_operations_base_record_version_check CHECK (
        base_record_version IS NULL OR base_record_version >= 0
    ),
    CONSTRAINT vault_operations_signature_schema_check CHECK (
        signature_schema = 'device-signature-v1'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS vault_operations_vault_sequence_uidx
    ON public.vault_operations(vault_id, sequence_number);

CREATE INDEX IF NOT EXISTS vault_operations_vault_record_idx
    ON public.vault_operations(vault_id, record_id, sequence_number);

CREATE INDEX IF NOT EXISTS vault_operations_user_idx
    ON public.vault_operations(user_id);

CREATE INDEX IF NOT EXISTS vault_operations_author_device_idx
    ON public.vault_operations(vault_id, author_device_id);

ALTER TABLE public.vault_operations ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vault_operations select own" ON public.vault_operations;
CREATE POLICY "vault_operations select own"
    ON public.vault_operations
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "vault_operations deny direct insert" ON public.vault_operations;
CREATE POLICY "vault_operations deny direct insert"
    ON public.vault_operations
    FOR INSERT
    TO authenticated
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_operations deny direct update" ON public.vault_operations;
CREATE POLICY "vault_operations deny direct update"
    ON public.vault_operations
    FOR UPDATE
    TO authenticated
    USING (false)
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_operations deny direct delete" ON public.vault_operations;
CREATE POLICY "vault_operations deny direct delete"
    ON public.vault_operations
    FOR DELETE
    TO authenticated
    USING (false);

REVOKE INSERT, UPDATE, DELETE ON public.vault_operations FROM authenticated;
GRANT SELECT ON public.vault_operations TO authenticated;

-- ---------------------------------------------------------------------------
-- 3. vault_device_trust_records — encrypted trusted-device list per vault.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.vault_device_trust_records (
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    public_signing_key TEXT NOT NULL,
    device_name_encrypted TEXT NOT NULL,
    added_by_device_id UUID,
    added_op_id UUID NOT NULL REFERENCES public.vault_operations(op_id) ON DELETE RESTRICT,
    added_at TIMESTAMPTZ NOT NULL,
    trust_epoch BIGINT NOT NULL CHECK (trust_epoch >= 0),
    status TEXT NOT NULL DEFAULT 'trusted',
    revoked_at TIMESTAMPTZ,
    revoked_by_device_id UUID,
    revoked_op_id UUID REFERENCES public.vault_operations(op_id) ON DELETE RESTRICT,
    PRIMARY KEY (vault_id, device_id),
    CONSTRAINT vault_device_trust_records_status_check CHECK (
        status IN ('trusted', 'revoked')
    ),
    CONSTRAINT vault_device_trust_records_revoke_consistency_check CHECK (
        (status = 'trusted' AND revoked_at IS NULL AND revoked_op_id IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_op_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS vault_device_trust_records_user_idx
    ON public.vault_device_trust_records(user_id);

ALTER TABLE public.vault_device_trust_records ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vault_device_trust_records select own" ON public.vault_device_trust_records;
CREATE POLICY "vault_device_trust_records select own"
    ON public.vault_device_trust_records
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "vault_device_trust_records deny direct insert" ON public.vault_device_trust_records;
CREATE POLICY "vault_device_trust_records deny direct insert"
    ON public.vault_device_trust_records
    FOR INSERT
    TO authenticated
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_device_trust_records deny direct update" ON public.vault_device_trust_records;
CREATE POLICY "vault_device_trust_records deny direct update"
    ON public.vault_device_trust_records
    FOR UPDATE
    TO authenticated
    USING (false)
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_device_trust_records deny direct delete" ON public.vault_device_trust_records;
CREATE POLICY "vault_device_trust_records deny direct delete"
    ON public.vault_device_trust_records
    FOR DELETE
    TO authenticated
    USING (false);

REVOKE INSERT, UPDATE, DELETE ON public.vault_device_trust_records FROM authenticated;
GRANT SELECT ON public.vault_device_trust_records TO authenticated;

-- ---------------------------------------------------------------------------
-- 4. vault_op_log_heads — current hash-chain head per vault.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.vault_op_log_heads (
    vault_id UUID PRIMARY KEY REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    current_head TEXT NOT NULL,
    current_op_id UUID,
    current_sequence_number BIGINT NOT NULL CHECK (current_sequence_number >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS vault_op_log_heads_user_idx
    ON public.vault_op_log_heads(user_id);

ALTER TABLE public.vault_op_log_heads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vault_op_log_heads select own" ON public.vault_op_log_heads;
CREATE POLICY "vault_op_log_heads select own"
    ON public.vault_op_log_heads
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "vault_op_log_heads deny direct insert" ON public.vault_op_log_heads;
CREATE POLICY "vault_op_log_heads deny direct insert"
    ON public.vault_op_log_heads
    FOR INSERT
    TO authenticated
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_op_log_heads deny direct update" ON public.vault_op_log_heads;
CREATE POLICY "vault_op_log_heads deny direct update"
    ON public.vault_op_log_heads
    FOR UPDATE
    TO authenticated
    USING (false)
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_op_log_heads deny direct delete" ON public.vault_op_log_heads;
CREATE POLICY "vault_op_log_heads deny direct delete"
    ON public.vault_op_log_heads
    FOR DELETE
    TO authenticated
    USING (false);

REVOKE INSERT, UPDATE, DELETE ON public.vault_op_log_heads FROM authenticated;
GRANT SELECT ON public.vault_op_log_heads TO authenticated;

COMMENT ON TABLE public.vault_records IS
    'Operation-log Phase 2: encrypted record store. Direct writes are denied; mutations go through public.submit_vault_operation.';
COMMENT ON TABLE public.vault_operations IS
    'Operation-log Phase 2: append-only signed operation log. The server enforces structural CAS only; signature/AAD verification stays client-side.';
COMMENT ON TABLE public.vault_device_trust_records IS
    'Operation-log Phase 2: per-vault trusted device list. Updated only via add_device / revoke_device operations.';
COMMENT ON TABLE public.vault_op_log_heads IS
    'Operation-log Phase 2: current hash-chain head per vault, used by the runtime to detect server-side rollback or fork.';
