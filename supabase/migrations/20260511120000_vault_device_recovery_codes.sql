-- ===========================================================================
-- Vault Device-Trust Recovery Codes
-- ---------------------------------------------------------------------------
-- Recovery codes are server-generated single-use verifiers. They do not create
-- trust by themselves: the operation log still carries signed
-- recovery_codes_rotate and recover_device operations for client verification.
-- ===========================================================================

ALTER TABLE public.vault_operations
    DROP CONSTRAINT IF EXISTS vault_operations_op_type_check;

ALTER TABLE public.vault_operations
    ADD CONSTRAINT vault_operations_op_type_check CHECK (
        op_type IN (
            'create',
            'update',
            'delete',
            'restore',
            'move',
            'rekey',
            'add_device',
            'revoke_device',
            'recovery_codes_rotate',
            'recover_device'
        )
    );

ALTER TABLE public.vault_operations
    DROP CONSTRAINT IF EXISTS vault_operations_signature_schema_check;

ALTER TABLE public.vault_operations
    ADD CONSTRAINT vault_operations_signature_schema_check CHECK (
        signature_schema IN ('device-signature-v1', 'device-signature-v2')
    );

ALTER TABLE public.rate_limit_attempts
    DROP CONSTRAINT IF EXISTS rate_limit_attempts_action_check;

ALTER TABLE public.rate_limit_attempts
    ADD CONSTRAINT rate_limit_attempts_action_check
    CHECK (
        action IN (
            'unlock',
            '2fa',
            'passkey',
            'emergency',
            'password_login',
            'recovery_request',
            'recovery_verify',
            'totp_verify',
            'backup_code_verify',
            'login_totp_verify',
            'login_backup_code_verify',
            'password_reset_totp_verify',
            'password_reset_backup_code_verify',
            'vault_totp_verify',
            'vault_backup_code_verify',
            'disable_2fa_verify',
            'critical_2fa_verify',
            'opaque_login',
            'opaque_reset',
            'opaque_register',
            'account_delete',
            'webauthn_challenge',
            'webauthn_verify',
            'webauthn_manage',
            'vault_recovery_code_redeem'
        )
    );

CREATE TABLE IF NOT EXISTS public.vault_recovery_code_sets (
    set_id UUID PRIMARY KEY,
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    activation_op_id UUID REFERENCES public.vault_operations(op_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    CONSTRAINT vault_recovery_code_sets_status_check CHECK (
        status IN ('pending', 'active', 'rotated', 'expired')
    ),
    CONSTRAINT vault_recovery_code_sets_activation_check CHECK (
        (status = 'pending' AND activation_op_id IS NULL AND activated_at IS NULL)
        OR (status <> 'pending')
    )
);

CREATE INDEX IF NOT EXISTS vault_recovery_code_sets_vault_status_idx
    ON public.vault_recovery_code_sets(vault_id, status);

CREATE TABLE IF NOT EXISTS public.vault_recovery_codes (
    code_id UUID PRIMARY KEY,
    set_id UUID NOT NULL REFERENCES public.vault_recovery_code_sets(set_id) ON DELETE CASCADE,
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    hash_version TEXT NOT NULL,
    commitment TEXT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    used_by_device_id UUID,
    used_by_request_id UUID REFERENCES public.vault_pending_device_requests(request_id) ON DELETE SET NULL,
    used_by_op_id UUID REFERENCES public.vault_operations(op_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT vault_recovery_codes_used_check CHECK (
        (is_used = FALSE AND used_at IS NULL AND used_by_device_id IS NULL AND used_by_op_id IS NULL)
        OR (is_used = TRUE AND used_at IS NOT NULL AND used_by_device_id IS NOT NULL AND used_by_op_id IS NOT NULL)
    ),
    CONSTRAINT vault_recovery_codes_hash_version_check CHECK (
        hash_version IN ('argon2id-v3')
    ),
    UNIQUE (set_id, commitment)
);

CREATE INDEX IF NOT EXISTS vault_recovery_codes_set_unused_idx
    ON public.vault_recovery_codes(set_id, is_used);

ALTER TABLE public.vault_recovery_code_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_recovery_codes ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "vault_recovery_code_sets deny direct select" ON public.vault_recovery_code_sets;
CREATE POLICY "vault_recovery_code_sets deny direct select"
    ON public.vault_recovery_code_sets
    FOR SELECT
    TO authenticated
    USING (false);

DROP POLICY IF EXISTS "vault_recovery_codes deny direct select" ON public.vault_recovery_codes;
CREATE POLICY "vault_recovery_codes deny direct select"
    ON public.vault_recovery_codes
    FOR SELECT
    TO authenticated
    USING (false);

DROP POLICY IF EXISTS "vault_recovery_code_sets deny direct writes" ON public.vault_recovery_code_sets;
CREATE POLICY "vault_recovery_code_sets deny direct writes"
    ON public.vault_recovery_code_sets
    FOR ALL
    TO authenticated
    USING (false)
    WITH CHECK (false);

DROP POLICY IF EXISTS "vault_recovery_codes deny direct writes" ON public.vault_recovery_codes;
CREATE POLICY "vault_recovery_codes deny direct writes"
    ON public.vault_recovery_codes
    FOR ALL
    TO authenticated
    USING (false)
    WITH CHECK (false);

REVOKE ALL ON public.vault_recovery_code_sets FROM authenticated;
REVOKE ALL ON public.vault_recovery_codes FROM authenticated;

CREATE OR REPLACE FUNCTION public.activate_vault_recovery_code_set(
    p_user_id UUID,
    p_set_id UUID,
    p_op JSONB
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
BEGIN
    IF COALESCE(auth.role(), '') <> 'service_role' THEN
        RAISE EXCEPTION 'Service role required';
    END IF;
    IF p_user_id IS NULL OR p_set_id IS NULL OR p_op IS NULL THEN
        RAISE EXCEPTION 'Invalid recovery activation payload';
    END IF;
    IF p_op->>'op_type' <> 'recovery_codes_rotate'
       OR p_op->>'record_type' <> 'manifest'
       OR p_op->>'signature_schema' <> 'device-signature-v2'
       OR _record_id <> p_set_id
       OR p_op->'signed_body'->>'recoveryCodeSetId' <> p_set_id::TEXT THEN
        RAISE EXCEPTION 'Invalid recovery rotation operation';
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
           OR _existing_op.op_type <> 'recovery_codes_rotate' THEN
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

    IF NOT EXISTS (
        SELECT 1 FROM public.vault_recovery_code_sets
        WHERE set_id = p_set_id AND vault_id = _vault_id AND user_id = p_user_id AND status = 'pending'
    ) THEN
        RAISE EXCEPTION 'Recovery code set is not pending';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM public.vault_device_trust_records
        WHERE vault_id = _vault_id
          AND device_id = _author_device_id
          AND user_id = p_user_id
          AND status = 'trusted'
    ) THEN
        RAISE EXCEPTION 'Author device is not trusted';
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
        _op_id, _op_hash, _vault_id, p_user_id, _author_device_id, 'recovery_codes_rotate',
        _record_id, 'manifest', NULL, NULL,
        NULL, _base_vault_head, _resulting_vault_head,
        NULL, NULL, p_op->'signed_body', p_op->>'signature',
        'device-signature-v2', COALESCE((p_op->>'trust_epoch')::BIGINT, 0), _created_at_client, _next_sequence,
        NULLIF(p_op->>'intent_id', '')::UUID, NULLIF(p_op->>'rebased_from_op_id', '')::UUID
    );

    UPDATE public.vault_recovery_code_sets
    SET status = 'rotated', rotated_at = NOW()
    WHERE vault_id = _vault_id AND user_id = p_user_id AND status = 'active';

    UPDATE public.vault_recovery_code_sets
    SET status = 'active', activation_op_id = _op_id, activated_at = NOW()
    WHERE set_id = p_set_id AND vault_id = _vault_id AND user_id = p_user_id;

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

REVOKE ALL ON FUNCTION public.activate_vault_recovery_code_set(UUID, UUID, JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.redeem_vault_recovery_code_for_device(UUID, UUID, UUID, JSONB, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.activate_vault_recovery_code_set(UUID, UUID, JSONB) TO service_role;
GRANT EXECUTE ON FUNCTION public.redeem_vault_recovery_code_for_device(UUID, UUID, UUID, JSONB, JSONB) TO service_role;
