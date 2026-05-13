-- Allow a valid recovery-code operation to revive a previously revoked device id.
-- Fresh databases also get this definition through 20260511120000; this follow-up
-- migration is needed for databases where the first recovery migration already ran.

CREATE OR REPLACE FUNCTION public.redeem_vault_recovery_code_for_device(
    p_user_id UUID,
    p_request_id UUID,
    p_code_id UUID,
    p_op JSONB,
    p_device_trust_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _op_id UUID := (p_op->>'op_id')::UUID;
    _op_hash TEXT := p_op->>'op_hash';
    _vault_id UUID := (p_op->>'vault_id')::UUID;
    _record_id UUID := (p_op->>'record_id')::UUID;
    _author_device_id UUID := (p_op->>'author_device_id')::UUID;
    _base_vault_head TEXT := NULLIF(p_op->>'base_vault_head', '');
    _resulting_vault_head TEXT := p_op->>'resulting_vault_head';
    _created_at_client TIMESTAMPTZ := (p_op->>'created_at_client')::TIMESTAMPTZ;
    _current_head_row public.vault_op_log_heads%ROWTYPE;
    _next_sequence BIGINT;
    _existing_op public.vault_operations%ROWTYPE;
    _existing_trust public.vault_device_trust_records%ROWTYPE;
    _code public.vault_recovery_codes%ROWTYPE;
    _request public.vault_pending_device_requests%ROWTYPE;
    _public_key TEXT;
BEGIN
    IF COALESCE(auth.role(), '') <> 'service_role' THEN
        RAISE EXCEPTION 'Service role required';
    END IF;
    IF p_user_id IS NULL OR p_request_id IS NULL OR p_code_id IS NULL OR p_op IS NULL THEN
        RAISE EXCEPTION 'Invalid recovery redeem payload';
    END IF;
    IF p_op->>'op_type' <> 'recover_device'
       OR p_op->>'record_type' <> 'device'
       OR p_op->>'signature_schema' <> 'device-signature-v2'
       OR _record_id <> _author_device_id
       OR _record_id <> (p_device_trust_payload->'device'->>'device_id')::UUID
       OR p_device_trust_payload->>'kind' <> 'recover' THEN
        RAISE EXCEPTION 'Invalid recover_device operation';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults WHERE id = _vault_id AND user_id = p_user_id
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

    SELECT * INTO _existing_op FROM public.vault_operations WHERE op_id = _op_id;
    IF FOUND THEN
        IF _existing_op.op_hash <> _op_hash
           OR _existing_op.vault_id <> _vault_id
           OR _existing_op.user_id <> p_user_id
           OR _existing_op.op_type <> 'recover_device' THEN
            RAISE EXCEPTION 'op_id reused with a different op_hash';
        END IF;
        RETURN jsonb_build_object(
            'applied', true,
            'idempotent', true,
            'op_id', _op_id,
            'sequence_number', _existing_op.sequence_number,
            'resulting_vault_head', _existing_op.resulting_vault_head,
            'current_head', _existing_op.resulting_vault_head
        );
    END IF;

    SELECT * INTO _code
    FROM public.vault_recovery_codes
    WHERE code_id = p_code_id
    FOR UPDATE;
    IF NOT FOUND OR _code.user_id <> p_user_id OR _code.vault_id <> _vault_id OR _code.is_used THEN
        RAISE EXCEPTION 'Recovery code is not usable';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.vault_recovery_code_sets
        WHERE set_id = _code.set_id
          AND vault_id = _vault_id
          AND user_id = p_user_id
          AND status = 'active'
    ) THEN
        RAISE EXCEPTION 'Recovery code set is not active';
    END IF;
    IF _code.commitment <> COALESCE(p_op->'signed_body'->>'recoveryCodeCommitment', '') THEN
        RAISE EXCEPTION 'Recovery commitment mismatch';
    END IF;

    SELECT * INTO _request
    FROM public.vault_pending_device_requests
    WHERE request_id = p_request_id
    FOR UPDATE;
    IF NOT FOUND
       OR _request.user_id <> p_user_id
       OR _request.vault_id <> _vault_id
       OR _request.status <> 'pending'
       OR _request.challenge_expires_at <= NOW()
       OR _request.requested_device_id <> _record_id THEN
        RAISE EXCEPTION 'Pending device request is not usable';
    END IF;
    _public_key := p_device_trust_payload->'device'->>'public_signing_key';
    IF _public_key IS NULL
       OR _public_key <> _request.requested_public_signing_key
       OR _public_key <> COALESCE(p_op->'signed_body'->>'targetPublicSigningKey', '') THEN
        RAISE EXCEPTION 'Recovered device key mismatch';
    END IF;

    SELECT * INTO _existing_trust
    FROM public.vault_device_trust_records
    WHERE vault_id = _vault_id AND device_id = _record_id
    FOR UPDATE;
    IF _existing_trust.vault_id IS NOT NULL AND _existing_trust.user_id <> p_user_id THEN
        RAISE EXCEPTION 'Device trust row belongs to another caller';
    END IF;
    IF _existing_trust.vault_id IS NOT NULL AND _existing_trust.status = 'trusted' THEN
        RAISE EXCEPTION 'Device already present in trust list';
    END IF;

    SELECT * INTO _current_head_row
    FROM public.vault_op_log_heads
    WHERE vault_id = _vault_id
    FOR UPDATE;

    IF FOUND THEN
        IF _current_head_row.user_id <> p_user_id THEN
            RAISE EXCEPTION 'Vault head row belongs to another caller';
        END IF;
        IF _base_vault_head IS NULL OR _current_head_row.current_head <> _base_vault_head THEN
            RAISE EXCEPTION 'stale_vault_head';
        END IF;
        _next_sequence := _current_head_row.current_sequence_number + 1;
    ELSE
        IF _base_vault_head IS NOT NULL THEN
            RAISE EXCEPTION 'stale_vault_head';
        END IF;
        _next_sequence := 1;
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
        _op_id, _op_hash, _vault_id, p_user_id, _author_device_id, 'recover_device',
        _record_id, 'device', NULL, NULL,
        NULL, _base_vault_head, _resulting_vault_head,
        NULL, NULL, p_op->'signed_body', p_op->>'signature',
        'device-signature-v2', 0, _created_at_client, _next_sequence,
        NULLIF(p_op->>'intent_id', '')::UUID, NULLIF(p_op->>'rebased_from_op_id', '')::UUID
    );

    IF _existing_trust.vault_id IS NOT NULL THEN
        UPDATE public.vault_device_trust_records
        SET public_signing_key = _public_key,
            device_name_encrypted = COALESCE(p_device_trust_payload->'device'->>'device_name_encrypted', ''),
            added_by_device_id = NULL,
            added_op_id = _op_id,
            added_at = _created_at_client,
            trust_epoch = 0,
            status = 'trusted',
            revoked_at = NULL,
            revoked_by_device_id = NULL,
            revoked_op_id = NULL
        WHERE vault_id = _vault_id AND device_id = _record_id AND user_id = p_user_id;
    ELSE
        INSERT INTO public.vault_device_trust_records (
            vault_id, device_id, user_id, public_signing_key,
            device_name_encrypted, added_by_device_id, added_op_id,
            added_at, trust_epoch, status
        )
        VALUES (
            _vault_id,
            _record_id,
            p_user_id,
            _public_key,
            COALESCE(p_device_trust_payload->'device'->>'device_name_encrypted', ''),
            NULL,
            _op_id,
            _created_at_client,
            0,
            'trusted'
        );
    END IF;

    UPDATE public.vault_recovery_codes
    SET is_used = TRUE,
        used_at = NOW(),
        used_by_device_id = _record_id,
        used_by_request_id = p_request_id,
        used_by_op_id = _op_id
    WHERE code_id = p_code_id;

    UPDATE public.vault_pending_device_requests
    SET status = 'approved',
        resolved_by_device_id = NULL,
        resolved_at = NOW(),
        updated_at = NOW()
    WHERE request_id = p_request_id;

    INSERT INTO public.vault_op_log_heads (
        vault_id, user_id, current_head, current_op_id,
        current_sequence_number, updated_at
    )
    VALUES (_vault_id, p_user_id, _resulting_vault_head, _op_id, _next_sequence, NOW())
    ON CONFLICT (vault_id) DO UPDATE
    SET current_head = EXCLUDED.current_head,
        current_op_id = EXCLUDED.current_op_id,
        current_sequence_number = EXCLUDED.current_sequence_number,
        updated_at = NOW()
    WHERE public.vault_op_log_heads.user_id = p_user_id;

    RETURN jsonb_build_object(
        'applied', true,
        'idempotent', false,
        'op_id', _op_id,
        'sequence_number', _next_sequence,
        'resulting_vault_head', _resulting_vault_head,
        'current_head', _resulting_vault_head
    );
END;
$$;

REVOKE ALL ON FUNCTION public.redeem_vault_recovery_code_for_device(UUID, UUID, UUID, JSONB, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.redeem_vault_recovery_code_for_device(UUID, UUID, UUID, JSONB, JSONB) TO service_role;
