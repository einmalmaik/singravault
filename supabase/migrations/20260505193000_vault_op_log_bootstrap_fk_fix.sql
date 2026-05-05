-- Phase 12 local/integration fix:
-- The initial device trust root is created by bootstrap_vault_trust before
-- any signed vault operation exists. Later device additions and revocations
-- still reference signed operations via submit_vault_operation.

ALTER TABLE public.vault_device_trust_records
    ALTER COLUMN added_op_id DROP NOT NULL;

COMMENT ON COLUMN public.vault_device_trust_records.added_op_id IS
    'NULL only for the initial bootstrap trust root. Non-bootstrap trust changes reference a signed vault operation.';

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
           o.previous_ciphertext_hash, o.new_record_hash, o.intent_id,
           o.rebased_from_op_id, o.base_vault_head, o.resulting_vault_head,
           o.payload_ciphertext_hash, o.payload_aad_hash, o.signed_body,
           o.signature, o.signature_schema, o.trust_epoch,
           o.created_at_client, o.received_at_server
    FROM public.vault_operations o
    WHERE o.vault_id = p_vault_id
      AND o.user_id = _uid
      AND o.sequence_number > COALESCE(p_since_sequence, 0)
    ORDER BY o.sequence_number ASC
    LIMIT _limit;
END;
$$;

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

    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

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
        NULL,
        NOW(),
        0,
        'trusted'
    );

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
