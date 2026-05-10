-- ===========================================================================
-- Vault Operation Log: allow device record_type for trust operations
-- ---------------------------------------------------------------------------
-- The client signs add_device operations with record_type = 'device'. This
-- keeps the target device id in the normal operation envelope without creating
-- a vault_records row. Trust is still established only by submit_vault_operation
-- applying the signed add_device operation and matching device_trust_payload.
-- ===========================================================================

ALTER TABLE public.vault_operations
    DROP CONSTRAINT IF EXISTS vault_operations_record_type_check;

ALTER TABLE public.vault_operations
    ADD CONSTRAINT vault_operations_record_type_check CHECK (
        record_type IN (
            'item',
            'category',
            'attachment_metadata',
            'attachment_chunk',
            'manifest',
            'tombstone',
            'device'
        )
    );

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
        'attachment_chunk', 'manifest', 'tombstone', 'device'
    ) THEN
        RAISE EXCEPTION 'Unsupported record_type';
    END IF;

    IF _op_type IN ('add_device', 'revoke_device') AND _record_type <> 'device' THEN
        RAISE EXCEPTION 'Device trust operations require record_type device';
    END IF;

    IF _op_type NOT IN ('add_device', 'revoke_device') AND _record_type = 'device' THEN
        RAISE EXCEPTION 'record_type device is only valid for device trust operations';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = _vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

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

    IF _op_type IN ('create', 'update', 'delete', 'restore', 'move', 'rekey') THEN
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

        IF _op_type = 'delete' THEN
            UPDATE public.vault_records
            SET record_version = record_version + 1,
                key_version = (p_record_payload->>'key_version')::BIGINT,
                aad_hash = p_record_payload->>'aad_hash',
                ciphertext_hash = p_record_payload->>'ciphertext_hash',
                nonce = p_record_payload->>'nonce',
                ciphertext = p_record_payload->>'ciphertext',
                is_tombstone = TRUE,
                last_op_id = _op_id,
                last_op_hash = _op_hash,
                updated_at = NOW()
            WHERE vault_id = _vault_id
              AND record_id = _record_id
              AND user_id = _uid;
        ELSE
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
        END IF;
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
            IF _trust_device_id <> _record_id THEN
                RAISE EXCEPTION 'device_trust_payload.device.device_id must match signed add_device record_id';
            END IF;
            IF COALESCE(p_device_trust_payload->'device'->>'public_signing_key', '') <> COALESCE(p_op->'signed_body'->>'targetPublicSigningKey', '') THEN
                RAISE EXCEPTION 'device_trust_payload public key must match signed add_device public key';
            END IF;
            IF COALESCE(p_op->'signed_body'->>'targetPublicSigningKey', '') = '' THEN
                RAISE EXCEPTION 'signed add_device targetPublicSigningKey is required';
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
