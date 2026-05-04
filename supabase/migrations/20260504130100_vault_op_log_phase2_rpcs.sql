-- ===========================================================================
-- Vault Operation Log — Phase 2 (RPCs)
-- ---------------------------------------------------------------------------
-- Companion to 20260504130000_vault_op_log_phase2_records_operations_trust.sql.
--
-- Four SECURITY DEFINER RPCs:
--   1. public.submit_vault_operation        — idempotent CAS write path.
--   2. public.get_vault_head                — fetch current hash-chain head.
--   3. public.get_vault_changes_since       — incremental fetch by sequence.
--   4. public.get_vault_records_by_ids      — on-demand record fetch.
--
-- The server is NOT a trust source. Signature and AAD verification are
-- the client's job. The server enforces only:
--   - vault_id ownership against auth.uid()
--   - op_id uniqueness (idempotent retry)
--   - base_record_version CAS against current vault_records.record_version
--   - previous_ciphertext_hash CAS against current vault_records.ciphertext_hash
--   - base_vault_head CAS against current vault_op_log_heads.current_head
--   - intent_id + rebased_from_op_id stored for rebase tracking (no server validation)
--   - record-existence rules per op_type (create vs. update/delete/...)
--   - device-trust list consistency for add_device / revoke_device
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- submit_vault_operation
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.submit_vault_operation(
    p_op JSONB,
    p_record_payload JSONB,
    p_device_trust_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _op_id UUID;
    _op_hash TEXT;
    _vault_id UUID;
    _record_id UUID;
    _record_type TEXT;
    _op_type TEXT;
    _author_device_id UUID;
    _base_record_version BIGINT;
    _previous_ciphertext_hash TEXT;
    _new_record_hash TEXT;
    _intent_id UUID;
    _rebased_from_op_id UUID;
    _base_vault_head TEXT;
    _resulting_vault_head TEXT;
    _payload_ciphertext_hash TEXT;
    _payload_aad_hash TEXT;
    _signature TEXT;
    _signature_schema TEXT;
    _signed_body JSONB;
    _trust_epoch BIGINT;
    _created_at_client TIMESTAMPTZ;

    _existing_op public.vault_operations%ROWTYPE;
    _existing_record public.vault_records%ROWTYPE;
    _record_exists BOOLEAN := FALSE;
    _current_head_row public.vault_op_log_heads%ROWTYPE;
    _next_sequence BIGINT;

    _trust_kind TEXT;
    _trust_device_id UUID;
    _trust_existing public.vault_device_trust_records%ROWTYPE;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;
    IF p_op IS NULL THEN
        RAISE EXCEPTION 'Operation payload is required';
    END IF;

    -- ----- Decode the operation envelope -----
    _op_id := (p_op->>'op_id')::UUID;
    _op_hash := p_op->>'op_hash';
    _vault_id := (p_op->>'vault_id')::UUID;
    _record_id := (p_op->>'record_id')::UUID;
    _record_type := p_op->>'record_type';
    _op_type := p_op->>'op_type';
    _author_device_id := (p_op->>'author_device_id')::UUID;
    _base_record_version := NULLIF(p_op->>'base_record_version', '')::BIGINT;
    _previous_ciphertext_hash := NULLIF(p_op->>'previous_ciphertext_hash', '');
    _new_record_hash := NULLIF(p_op->>'new_record_hash', '');
    _intent_id := NULLIF(p_op->>'intent_id', '')::UUID;
    _rebased_from_op_id := NULLIF(p_op->>'rebased_from_op_id', '')::UUID;
    _base_vault_head := NULLIF(p_op->>'base_vault_head', '');
    _resulting_vault_head := p_op->>'resulting_vault_head';
    _payload_ciphertext_hash := NULLIF(p_op->>'payload_ciphertext_hash', '');
    _payload_aad_hash := NULLIF(p_op->>'payload_aad_hash', '');
    _signature := p_op->>'signature';
    _signature_schema := p_op->>'signature_schema';
    _signed_body := p_op->'signed_body';
    _trust_epoch := COALESCE((p_op->>'trust_epoch')::BIGINT, 0);
    _created_at_client := (p_op->>'created_at_client')::TIMESTAMPTZ;

    IF _op_id IS NULL OR _op_hash IS NULL OR _vault_id IS NULL
       OR _record_id IS NULL OR _record_type IS NULL OR _op_type IS NULL
       OR _author_device_id IS NULL OR _resulting_vault_head IS NULL
       OR _signature IS NULL OR _signature_schema IS NULL
       OR _signed_body IS NULL OR _created_at_client IS NULL THEN
        RAISE EXCEPTION 'Operation payload is missing required fields';
    END IF;

    IF _signature_schema <> 'device-signature-v1' THEN
        RAISE EXCEPTION 'Unsupported signature_schema';
    END IF;

    IF _op_type NOT IN (
        'create', 'update', 'delete', 'restore', 'move',
        'rekey', 'add_device', 'revoke_device'
    ) THEN
        RAISE EXCEPTION 'Unsupported op_type';
    END IF;

    IF _record_type NOT IN (
        'item', 'category', 'attachment_metadata',
        'attachment_chunk', 'manifest', 'tombstone'
    ) THEN
        RAISE EXCEPTION 'Unsupported record_type';
    END IF;

    -- ----- Vault ownership check -----
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = _vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

    -- ----- Idempotent retry: same op_id already persisted -----
    SELECT * INTO _existing_op
    FROM public.vault_operations
    WHERE op_id = _op_id;

    IF FOUND THEN
        IF _existing_op.op_hash <> _op_hash THEN
            RAISE EXCEPTION 'op_id reused with a different op_hash';
        END IF;
        IF _existing_op.user_id <> _uid OR _existing_op.vault_id <> _vault_id THEN
            RAISE EXCEPTION 'op_id belongs to another caller';
        END IF;

        SELECT * INTO _current_head_row
        FROM public.vault_op_log_heads
        WHERE vault_id = _vault_id;

        RETURN jsonb_build_object(
            'applied', true,
            'idempotent', true,
            'op_id', _op_id,
            'sequence_number', _existing_op.sequence_number,
            'resulting_vault_head', _existing_op.resulting_vault_head,
            'current_head', COALESCE(_current_head_row.current_head, _existing_op.resulting_vault_head),
            'current_sequence_number', COALESCE(_current_head_row.current_sequence_number, _existing_op.sequence_number),
            'conflict_reason', NULL
        );
    END IF;

    -- ----- Lock the head row for the vault -----
    SELECT * INTO _current_head_row
    FROM public.vault_op_log_heads
    WHERE vault_id = _vault_id
    FOR UPDATE;

    IF FOUND THEN
        IF _current_head_row.user_id <> _uid THEN
            RAISE EXCEPTION 'Vault head row belongs to another caller';
        END IF;
        IF _base_vault_head IS NULL OR _current_head_row.current_head <> _base_vault_head THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_vault_head',
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
        _next_sequence := _current_head_row.current_sequence_number + 1;
    ELSE
        IF _base_vault_head IS NOT NULL THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_vault_head',
                'current_head', NULL,
                'current_sequence_number', 0
            );
        END IF;
        _next_sequence := 1;
    END IF;

    -- ----- Lock the record row (if it exists) -----
    SELECT * INTO _existing_record
    FROM public.vault_records
    WHERE vault_id = _vault_id AND record_id = _record_id
    FOR UPDATE;
    _record_exists := FOUND;

    IF _record_exists THEN
        IF _existing_record.user_id <> _uid THEN
            RAISE EXCEPTION 'Record belongs to another caller';
        END IF;
        IF _existing_record.record_type <> _record_type THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'record_type_mismatch',
                'current_record_version', _existing_record.record_version,
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
    END IF;

    -- ----- CAS on base_record_version and previous_ciphertext_hash -----
    IF _op_type = 'create' THEN
        IF _record_exists AND NOT _existing_record.is_tombstone THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'record_already_exists',
                'current_record_version', _existing_record.record_version,
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
        IF _base_record_version IS NOT NULL OR _previous_ciphertext_hash IS NOT NULL THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'create_must_not_carry_base'
            );
        END IF;
    ELSIF _op_type IN ('add_device', 'revoke_device') THEN
        -- Trust ops are not record-CAS gated in the same way; the trust
        -- list is updated separately below. They still consume a sequence
        -- number and must carry a valid base_vault_head.
        NULL;
    ELSE
        IF NOT _record_exists THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'record_not_found',
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
        IF _base_record_version IS NULL
           OR _existing_record.record_version <> _base_record_version THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_record_version',
                'current_record_version', _existing_record.record_version,
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
        IF _previous_ciphertext_hash IS NULL
           OR _existing_record.ciphertext_hash <> _previous_ciphertext_hash THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_previous_ciphertext_hash',
                'current_record_version', _existing_record.record_version,
                'current_head', _current_head_row.current_head,
                'current_sequence_number', _current_head_row.current_sequence_number
            );
        END IF;
    END IF;

    -- ----- Insert the operation row (append-only) -----
    INSERT INTO public.vault_operations (
        op_id, op_hash, vault_id, user_id, author_device_id, op_type,
        record_id, record_type, base_record_version, previous_ciphertext_hash,
        new_record_hash, base_vault_head, resulting_vault_head,
        payload_ciphertext_hash, payload_aad_hash, signed_body, signature,
        signature_schema, trust_epoch, created_at_client, sequence_number,
        intent_id, rebased_from_op_id
    )
    VALUES (
        _op_id, _op_hash, _vault_id, _uid, _author_device_id, _op_type,
        _record_id, _record_type, _base_record_version, _previous_ciphertext_hash,
        _new_record_hash, _base_vault_head, _resulting_vault_head,
        _payload_ciphertext_hash, _payload_aad_hash, _signed_body, _signature,
        _signature_schema, _trust_epoch, _created_at_client, _next_sequence,
        _intent_id, _rebased_from_op_id
    );

    -- ----- Apply the record-level effect -----
    IF _op_type IN ('create', 'update', 'restore', 'move', 'rekey') THEN
        IF p_record_payload IS NULL THEN
            RAISE EXCEPTION 'record_payload is required for op_type %', _op_type;
        END IF;
        IF p_record_payload->>'aad_hash' IS NULL
           OR p_record_payload->>'ciphertext_hash' IS NULL
           OR p_record_payload->>'nonce' IS NULL
           OR p_record_payload->>'ciphertext' IS NULL
           OR p_record_payload->>'key_version' IS NULL THEN
            RAISE EXCEPTION 'record_payload is missing required fields';
        END IF;
        IF (p_record_payload->>'aad_hash') <> COALESCE(_payload_aad_hash, '') THEN
            RAISE EXCEPTION 'record_payload aad_hash does not match operation';
        END IF;
        IF (p_record_payload->>'ciphertext_hash') <> COALESCE(_payload_ciphertext_hash, '') THEN
            RAISE EXCEPTION 'record_payload ciphertext_hash does not match operation';
        END IF;

        INSERT INTO public.vault_records (
            vault_id, record_id, user_id, record_type, record_version,
            key_version, aad_hash, ciphertext_hash, nonce, ciphertext,
            last_op_id, last_op_hash, is_tombstone, created_at, updated_at
        )
        VALUES (
            _vault_id,
            _record_id,
            _uid,
            _record_type,
            CASE WHEN _record_exists THEN _existing_record.record_version + 1 ELSE 1 END,
            (p_record_payload->>'key_version')::BIGINT,
            p_record_payload->>'aad_hash',
            p_record_payload->>'ciphertext_hash',
            p_record_payload->>'nonce',
            p_record_payload->>'ciphertext',
            _op_id,
            _op_hash,
            FALSE,
            COALESCE(_existing_record.created_at, NOW()),
            NOW()
        )
        ON CONFLICT (vault_id, record_id) DO UPDATE
        SET record_version = EXCLUDED.record_version,
            key_version = EXCLUDED.key_version,
            aad_hash = EXCLUDED.aad_hash,
            ciphertext_hash = EXCLUDED.ciphertext_hash,
            nonce = EXCLUDED.nonce,
            ciphertext = EXCLUDED.ciphertext,
            last_op_id = EXCLUDED.last_op_id,
            last_op_hash = EXCLUDED.last_op_hash,
            is_tombstone = FALSE,
            updated_at = NOW()
        WHERE public.vault_records.user_id = _uid;
    ELSIF _op_type = 'delete' THEN
        UPDATE public.vault_records
        SET record_version = record_version + 1,
            is_tombstone = TRUE,
            last_op_id = _op_id,
            last_op_hash = _op_hash,
            -- Keep ciphertext columns so a `restore` can be a pure
            -- record-version bump on the same physical row.
            updated_at = NOW()
        WHERE vault_id = _vault_id
          AND record_id = _record_id
          AND user_id = _uid;
    ELSIF _op_type IN ('add_device', 'revoke_device') THEN
        IF p_device_trust_payload IS NULL THEN
            RAISE EXCEPTION 'device_trust_payload is required for op_type %', _op_type;
        END IF;
        _trust_kind := p_device_trust_payload->>'kind';
        IF _trust_kind IS NULL THEN
            RAISE EXCEPTION 'device_trust_payload.kind is required';
        END IF;

        IF _op_type = 'add_device' THEN
            IF _trust_kind <> 'add' THEN
                RAISE EXCEPTION 'device_trust_payload.kind does not match op_type add_device';
            END IF;
            _trust_device_id := (p_device_trust_payload->'device'->>'device_id')::UUID;
            IF _trust_device_id IS NULL THEN
                RAISE EXCEPTION 'device_trust_payload.device.device_id is required';
            END IF;
            IF EXISTS (
                SELECT 1 FROM public.vault_device_trust_records
                WHERE vault_id = _vault_id AND device_id = _trust_device_id
            ) THEN
                RAISE EXCEPTION 'Device already present in trust list';
            END IF;
            INSERT INTO public.vault_device_trust_records (
                vault_id, device_id, user_id, public_signing_key,
                device_name_encrypted, added_by_device_id, added_op_id,
                added_at, trust_epoch, status
            )
            VALUES (
                _vault_id,
                _trust_device_id,
                _uid,
                p_device_trust_payload->'device'->>'public_signing_key',
                p_device_trust_payload->'device'->>'device_name_encrypted',
                NULLIF(p_device_trust_payload->'device'->>'added_by_device_id', '')::UUID,
                _op_id,
                COALESCE(
                    (p_device_trust_payload->'device'->>'added_at')::TIMESTAMPTZ,
                    _created_at_client
                ),
                COALESCE((p_device_trust_payload->'device'->>'trust_epoch')::BIGINT, _trust_epoch),
                'trusted'
            );
        ELSE
            IF _trust_kind <> 'revoke' THEN
                RAISE EXCEPTION 'device_trust_payload.kind does not match op_type revoke_device';
            END IF;
            _trust_device_id := (p_device_trust_payload->>'device_id')::UUID;
            IF _trust_device_id IS NULL THEN
                RAISE EXCEPTION 'device_trust_payload.device_id is required';
            END IF;
            SELECT * INTO _trust_existing
            FROM public.vault_device_trust_records
            WHERE vault_id = _vault_id AND device_id = _trust_device_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'Device not present in trust list';
            END IF;
            IF _trust_existing.user_id <> _uid THEN
                RAISE EXCEPTION 'Trust record belongs to another caller';
            END IF;
            UPDATE public.vault_device_trust_records
            SET status = 'revoked',
                revoked_at = COALESCE(
                    (p_device_trust_payload->>'revoked_at')::TIMESTAMPTZ,
                    _created_at_client
                ),
                revoked_by_device_id = _author_device_id,
                revoked_op_id = _op_id,
                trust_epoch = trust_epoch + 1
            WHERE vault_id = _vault_id AND device_id = _trust_device_id;
        END IF;
    END IF;

    -- ----- Advance the head row -----
    INSERT INTO public.vault_op_log_heads (
        vault_id, user_id, current_head, current_op_id,
        current_sequence_number, updated_at
    )
    VALUES (
        _vault_id, _uid, _resulting_vault_head, _op_id,
        _next_sequence, NOW()
    )
    ON CONFLICT (vault_id) DO UPDATE
    SET current_head = EXCLUDED.current_head,
        current_op_id = EXCLUDED.current_op_id,
        current_sequence_number = EXCLUDED.current_sequence_number,
        updated_at = NOW()
    WHERE public.vault_op_log_heads.user_id = _uid;

    RETURN jsonb_build_object(
        'applied', true,
        'idempotent', false,
        'op_id', _op_id,
        'sequence_number', _next_sequence,
        'resulting_vault_head', _resulting_vault_head,
        'current_head', _resulting_vault_head,
        'current_sequence_number', _next_sequence,
        'conflict_reason', NULL
    );
END;
$$;

REVOKE ALL ON FUNCTION public.submit_vault_operation(JSONB, JSONB, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.submit_vault_operation(JSONB, JSONB, JSONB) TO authenticated;

COMMENT ON FUNCTION public.submit_vault_operation(JSONB, JSONB, JSONB) IS
    'Operation-log Phase 2: idempotent CAS write path. Enforces vault ownership, op_id uniqueness, base_record_version, previous_ciphertext_hash, base_vault_head and per-op-type record-existence rules. Returns conflict_reason instead of raising for CAS misses. Stores intent_id and rebased_from_op_id for rebase tracking.';

-- ---------------------------------------------------------------------------
-- get_vault_head
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_vault_head(p_vault_id UUID)
RETURNS TABLE(
    vault_id UUID,
    current_head TEXT,
    current_op_id UUID,
    current_sequence_number BIGINT,
    updated_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT h.vault_id, h.current_head, h.current_op_id,
           h.current_sequence_number, h.updated_at
    FROM public.vault_op_log_heads h
    WHERE h.vault_id = p_vault_id
      AND h.user_id = auth.uid();
$$;

REVOKE ALL ON FUNCTION public.get_vault_head(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_vault_head(UUID) TO authenticated;

COMMENT ON FUNCTION public.get_vault_head(UUID) IS
    'Operation-log Phase 2: returns the caller-owned vault hash-chain head. Clients persist this as lastVerifiedVaultHead and use it as base_vault_head for the next operation.';

-- ---------------------------------------------------------------------------
-- get_vault_changes_since
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_vault_changes_since(
    p_vault_id UUID,
    p_since_sequence BIGINT,
    p_limit INTEGER
)
RETURNS TABLE(
    op_id UUID,
    op_hash TEXT,
    sequence_number BIGINT,
    author_device_id UUID,
    op_type TEXT,
    record_id UUID,
    record_type TEXT,
    base_record_version BIGINT,
    previous_ciphertext_hash TEXT,
    new_record_hash TEXT,
    intent_id UUID,
    rebased_from_op_id UUID,
    base_vault_head TEXT,
    resulting_vault_head TEXT,
    payload_ciphertext_hash TEXT,
    payload_aad_hash TEXT,
    signed_body JSONB,
    signature TEXT,
    signature_schema TEXT,
    trust_epoch BIGINT,
    created_at_client TIMESTAMPTZ,
    received_at_server TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _limit INTEGER := COALESCE(p_limit, 500);
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;
    IF _limit < 1 OR _limit > 1000 THEN
        RAISE EXCEPTION 'p_limit must be between 1 and 1000';
    END IF;

    RETURN QUERY
    SELECT o.op_id, o.op_hash, o.sequence_number, o.author_device_id,
           o.op_type, o.record_id, o.record_type, o.base_record_version,
           o.previous_ciphertext_hash, o.new_record_hash, o.base_vault_head,
           o.resulting_vault_head, o.payload_ciphertext_hash, o.payload_aad_hash,
           o.signed_body, o.signature, o.signature_schema, o.trust_epoch,
           o.created_at_client, o.received_at_server, o.intent_id, o.rebased_from_op_id
    FROM public.vault_operations o
    WHERE o.vault_id = p_vault_id
      AND o.user_id = _uid
      AND o.sequence_number > COALESCE(p_since_sequence, 0)
    ORDER BY o.sequence_number ASC
    LIMIT _limit;
END;
$$;

REVOKE ALL ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) TO authenticated;

COMMENT ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) IS
    'Operation-log Phase 2: returns operations newer than p_since_sequence in append order. The client verifies each signature, hashes and chain link against the locally trusted head before integrating.';

-- ---------------------------------------------------------------------------
-- get_vault_records_by_ids
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.get_vault_records_by_ids(
    p_vault_id UUID,
    p_record_ids UUID[]
)
RETURNS TABLE(
    vault_id UUID,
    record_id UUID,
    record_type TEXT,
    record_version BIGINT,
    key_version BIGINT,
    aad_hash TEXT,
    ciphertext_hash TEXT,
    nonce TEXT,
    ciphertext TEXT,
    last_op_id UUID,
    last_op_hash TEXT,
    is_tombstone BOOLEAN,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;
    IF p_record_ids IS NULL OR array_length(p_record_ids, 1) IS NULL THEN
        RETURN;
    END IF;
    IF array_length(p_record_ids, 1) > 500 THEN
        RAISE EXCEPTION 'Too many record ids in a single fetch';
    END IF;

    RETURN QUERY
    SELECT r.vault_id, r.record_id, r.record_type, r.record_version,
           r.key_version, r.aad_hash, r.ciphertext_hash, r.nonce,
           r.ciphertext, r.last_op_id, r.last_op_hash, r.is_tombstone,
           r.created_at, r.updated_at
    FROM public.vault_records r
    WHERE r.vault_id = p_vault_id
      AND r.user_id = _uid
      AND r.record_id = ANY(p_record_ids);
END;
$$;

REVOKE ALL ON FUNCTION public.get_vault_records_by_ids(UUID, UUID[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_vault_records_by_ids(UUID, UUID[]) TO authenticated;

COMMENT ON FUNCTION public.get_vault_records_by_ids(UUID, UUID[]) IS
    'Operation-log Phase 2: on-demand record fetch by id. The client verifies each record AAD/ciphertext hash against its locally trusted operation log before opening.';

-- ---------------------------------------------------------------------------
-- bootstrap_vault_trust
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.bootstrap_vault_trust(
    p_vault_id UUID,
    p_device_id UUID,
    p_public_signing_key TEXT,
    p_device_name_encrypted TEXT,
    p_initial_head TEXT,
    p_initial_op_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _existing_trust_count BIGINT;
    _existing_head public.vault_op_log_heads%ROWTYPE;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;
    IF p_vault_id IS NULL OR p_device_id IS NULL OR p_public_signing_key IS NULL
       OR p_device_name_encrypted IS NULL OR p_initial_head IS NULL OR p_initial_op_id IS NULL THEN
        RAISE EXCEPTION 'All parameters are required';
    END IF;

    -- ----- Vault ownership check -----
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

    -- ----- One-time bootstrap: only if no trust list exists -----
    SELECT COUNT(*) INTO _existing_trust_count
    FROM public.vault_device_trust_records
    WHERE vault_id = p_vault_id;

    IF _existing_trust_count > 0 THEN
        RETURN jsonb_build_object(
            'bootstrapped', false,
            'reason', 'trust_list_already_exists',
            'existing_count', _existing_trust_count
        );
    END IF;

    -- ----- One-time bootstrap: only if no head exists -----
    SELECT * INTO _existing_head
    FROM public.vault_op_log_heads
    WHERE vault_id = p_vault_id;

    IF FOUND THEN
        RETURN jsonb_build_object(
            'bootstrapped', false,
            'reason', 'head_already_exists',
            'current_head', _existing_head.current_head
        );
    END IF;

    -- ----- Insert the first trusted device -----
    INSERT INTO public.vault_device_trust_records (
        vault_id, device_id, user_id, public_signing_key,
        device_name_encrypted, added_by_device_id, added_op_id,
        added_at, trust_epoch, status
    )
    VALUES (
        p_vault_id,
        p_device_id,
        _uid,
        p_public_signing_key,
        p_device_name_encrypted,
        p_device_id,
        p_initial_op_id,
        NOW(),
        0,
        'trusted'
    );

    -- ----- Insert the initial head -----
    INSERT INTO public.vault_op_log_heads (
        vault_id, user_id, current_head, current_op_id,
        current_sequence_number, updated_at
    )
    VALUES (
        p_vault_id, _uid, p_initial_head, p_initial_op_id, 0, NOW()
    );

    RETURN jsonb_build_object(
        'bootstrapped', true,
        'vault_id', p_vault_id,
        'device_id', p_device_id,
        'initial_head', p_initial_head,
        'initial_op_id', p_initial_op_id
    );
END;
$$;

REVOKE ALL ON FUNCTION public.bootstrap_vault_trust(UUID, UUID, TEXT, TEXT, TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.bootstrap_vault_trust(UUID, UUID, TEXT, TEXT, TEXT, UUID) TO authenticated;

COMMENT ON FUNCTION public.bootstrap_vault_trust(UUID, UUID, TEXT, TEXT, TEXT, UUID) IS
    'Operation-log Phase 2: one-time bootstrap for a vault with no trust list and no head. Creates the first trusted device and the initial hash-chain head. Returns bootstrapped=false if already initialized.';
