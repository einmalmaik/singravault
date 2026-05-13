-- ============================================================================
-- Signed Collection Operation Log
-- ----------------------------------------------------------------------------
-- Shared Collections are cross-user data. They cannot be folded into a single
-- user's vault_op_log without confusing subscription entitlement with crypto
-- trust. This schema mirrors the vault operation-log invariants for collections:
-- direct writes are denied; mutations go through submit_collection_operation;
-- the server enforces only ownership/membership and CAS, never crypto trust.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.collection_op_log_heads (
    collection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    current_head TEXT,
    current_op_id UUID,
    current_sequence_number BIGINT NOT NULL DEFAULT 0 CHECK (current_sequence_number >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.collection_op_log_members (
    collection_id UUID NOT NULL REFERENCES public.collection_op_log_heads(collection_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('owner', 'view', 'edit')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    added_op_id UUID,
    removed_op_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collection_id, user_id)
);

CREATE TABLE IF NOT EXISTS public.collection_op_log_key_envelopes (
    collection_id UUID NOT NULL REFERENCES public.collection_op_log_heads(collection_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    key_version BIGINT NOT NULL CHECK (key_version >= 1),
    wrapped_key TEXT NOT NULL,
    pq_wrapped_key TEXT NOT NULL,
    added_op_id UUID,
    revoked_op_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (collection_id, user_id, key_version)
);

CREATE TABLE IF NOT EXISTS public.collection_records (
    collection_id UUID NOT NULL REFERENCES public.collection_op_log_heads(collection_id) ON DELETE CASCADE,
    record_id UUID NOT NULL,
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
    PRIMARY KEY (collection_id, record_id),
    CONSTRAINT collection_records_record_type_check CHECK (
        record_type IN (
            'collection_metadata',
            'collection_member',
            'collection_item',
            'collection_key',
            'tombstone'
        )
    )
);

CREATE TABLE IF NOT EXISTS public.collection_operations (
    op_id UUID PRIMARY KEY,
    op_hash TEXT NOT NULL UNIQUE,
    collection_id UUID NOT NULL REFERENCES public.collection_op_log_heads(collection_id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    actor_vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    author_device_id UUID NOT NULL,
    op_type TEXT NOT NULL,
    record_id UUID NOT NULL,
    record_type TEXT NOT NULL,
    base_record_version BIGINT,
    previous_ciphertext_hash TEXT,
    new_record_hash TEXT,
    base_collection_head TEXT,
    resulting_collection_head TEXT NOT NULL,
    payload_ciphertext_hash TEXT,
    payload_aad_hash TEXT,
    signed_body JSONB NOT NULL,
    signature TEXT NOT NULL,
    signature_schema TEXT NOT NULL,
    trust_epoch BIGINT NOT NULL CHECK (trust_epoch >= 0),
    created_at_client TIMESTAMPTZ NOT NULL,
    received_at_server TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sequence_number BIGINT NOT NULL CHECK (sequence_number >= 1),
    CONSTRAINT collection_operations_op_type_check CHECK (
        op_type IN (
            'create',
            'update',
            'delete',
            'restore',
            'rekey',
            'add_member',
            'remove_member',
            'update_member_permission'
        )
    ),
    CONSTRAINT collection_operations_record_type_check CHECK (
        record_type IN (
            'collection_metadata',
            'collection_member',
            'collection_item',
            'collection_key',
            'tombstone'
        )
    ),
    CONSTRAINT collection_operations_signature_schema_check CHECK (
        signature_schema = 'device-signature-v1'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS collection_operations_sequence_uidx
    ON public.collection_operations(collection_id, sequence_number);

CREATE INDEX IF NOT EXISTS collection_operations_record_idx
    ON public.collection_operations(collection_id, record_id, sequence_number);

CREATE INDEX IF NOT EXISTS collection_operations_actor_idx
    ON public.collection_operations(actor_user_id);

CREATE INDEX IF NOT EXISTS collection_records_type_idx
    ON public.collection_records(collection_id, record_type);

ALTER TABLE public.collection_op_log_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collection_op_log_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collection_op_log_key_envelopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collection_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.collection_operations ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.is_collection_op_log_active_member(_collection_id UUID, _user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.collection_op_log_members m
        WHERE m.collection_id = _collection_id
          AND m.user_id = _user_id
          AND m.status = 'active'
    );
$$;

CREATE OR REPLACE FUNCTION public.is_collection_op_log_editor(_collection_id UUID, _user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.collection_op_log_members m
        WHERE m.collection_id = _collection_id
          AND m.user_id = _user_id
          AND m.status = 'active'
          AND m.permission IN ('owner', 'edit')
    );
$$;

CREATE POLICY "collection heads active members can read"
    ON public.collection_op_log_heads
    FOR SELECT
    TO authenticated
    USING (public.is_collection_op_log_active_member(collection_id, auth.uid()));

CREATE POLICY "collection members active members can read"
    ON public.collection_op_log_members
    FOR SELECT
    TO authenticated
    USING (public.is_collection_op_log_active_member(collection_id, auth.uid()));

CREATE POLICY "collection key envelopes recipients can read"
    ON public.collection_op_log_key_envelopes
    FOR SELECT
    TO authenticated
    USING (user_id = auth.uid() AND public.is_collection_op_log_active_member(collection_id, auth.uid()));

CREATE POLICY "collection records active members can read"
    ON public.collection_records
    FOR SELECT
    TO authenticated
    USING (public.is_collection_op_log_active_member(collection_id, auth.uid()));

CREATE POLICY "collection operations active members can read"
    ON public.collection_operations
    FOR SELECT
    TO authenticated
    USING (public.is_collection_op_log_active_member(collection_id, auth.uid()));

CREATE POLICY "collection heads deny direct insert"
    ON public.collection_op_log_heads FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "collection heads deny direct update"
    ON public.collection_op_log_heads FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "collection heads deny direct delete"
    ON public.collection_op_log_heads FOR DELETE TO authenticated USING (false);

CREATE POLICY "collection members deny direct insert"
    ON public.collection_op_log_members FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "collection members deny direct update"
    ON public.collection_op_log_members FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "collection members deny direct delete"
    ON public.collection_op_log_members FOR DELETE TO authenticated USING (false);

CREATE POLICY "collection key envelopes deny direct insert"
    ON public.collection_op_log_key_envelopes FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "collection key envelopes deny direct update"
    ON public.collection_op_log_key_envelopes FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "collection key envelopes deny direct delete"
    ON public.collection_op_log_key_envelopes FOR DELETE TO authenticated USING (false);

CREATE POLICY "collection records deny direct insert"
    ON public.collection_records FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "collection records deny direct update"
    ON public.collection_records FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "collection records deny direct delete"
    ON public.collection_records FOR DELETE TO authenticated USING (false);

CREATE POLICY "collection operations deny direct insert"
    ON public.collection_operations FOR INSERT TO authenticated WITH CHECK (false);
CREATE POLICY "collection operations deny direct update"
    ON public.collection_operations FOR UPDATE TO authenticated USING (false) WITH CHECK (false);
CREATE POLICY "collection operations deny direct delete"
    ON public.collection_operations FOR DELETE TO authenticated USING (false);

REVOKE INSERT, UPDATE, DELETE ON public.collection_op_log_heads FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.collection_op_log_members FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.collection_op_log_key_envelopes FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.collection_records FROM authenticated;
REVOKE INSERT, UPDATE, DELETE ON public.collection_operations FROM authenticated;
GRANT SELECT ON public.collection_op_log_heads TO authenticated;
GRANT SELECT ON public.collection_op_log_members TO authenticated;
GRANT SELECT ON public.collection_op_log_key_envelopes TO authenticated;
GRANT SELECT ON public.collection_records TO authenticated;
GRANT SELECT ON public.collection_operations TO authenticated;

CREATE OR REPLACE FUNCTION public.submit_collection_operation(
    p_op JSONB,
    p_record_payload JSONB,
    p_key_envelope JSONB DEFAULT NULL
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
    _collection_id UUID;
    _actor_vault_id UUID;
    _author_device_id UUID;
    _op_type TEXT;
    _record_id UUID;
    _record_type TEXT;
    _base_record_version BIGINT;
    _previous_ciphertext_hash TEXT;
    _new_record_hash TEXT;
    _base_collection_head TEXT;
    _resulting_collection_head TEXT;
    _payload_ciphertext_hash TEXT;
    _payload_aad_hash TEXT;
    _signed_body JSONB;
    _signature TEXT;
    _signature_schema TEXT;
    _trust_epoch BIGINT;
    _created_at_client TIMESTAMPTZ;
    _existing_op public.collection_operations%ROWTYPE;
    _existing_record public.collection_records%ROWTYPE;
    _head public.collection_op_log_heads%ROWTYPE;
    _next_sequence BIGINT;
    _record_exists BOOLEAN := FALSE;
    _payload_kind TEXT;
    _target_user_id UUID;
    _target_permission TEXT;
    _key_recipient_user_id UUID;
    _key_version BIGINT;
    _wrapped_key TEXT;
    _pq_wrapped_key TEXT;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    _op_id := (p_op->>'op_id')::UUID;
    _op_hash := p_op->>'op_hash';
    _collection_id := (p_op->>'collection_id')::UUID;
    _actor_vault_id := (p_op->>'actor_vault_id')::UUID;
    _author_device_id := (p_op->>'author_device_id')::UUID;
    _op_type := p_op->>'op_type';
    _record_id := (p_op->>'record_id')::UUID;
    _record_type := p_op->>'record_type';
    _base_record_version := NULLIF(p_op->>'base_record_version', '')::BIGINT;
    _previous_ciphertext_hash := NULLIF(p_op->>'previous_ciphertext_hash', '');
    _new_record_hash := NULLIF(p_op->>'new_record_hash', '');
    _base_collection_head := NULLIF(p_op->>'base_collection_head', '');
    _resulting_collection_head := p_op->>'resulting_collection_head';
    _payload_ciphertext_hash := NULLIF(p_op->>'payload_ciphertext_hash', '');
    _payload_aad_hash := NULLIF(p_op->>'payload_aad_hash', '');
    _signed_body := p_op->'signed_body';
    _signature := p_op->>'signature';
    _signature_schema := p_op->>'signature_schema';
    _trust_epoch := COALESCE((p_op->>'trust_epoch')::BIGINT, 0);
    _created_at_client := (p_op->>'created_at_client')::TIMESTAMPTZ;

    IF _op_id IS NULL OR _op_hash IS NULL OR _collection_id IS NULL
       OR _actor_vault_id IS NULL OR _author_device_id IS NULL
       OR _op_type IS NULL OR _record_id IS NULL OR _record_type IS NULL
       OR _resulting_collection_head IS NULL OR _signed_body IS NULL
       OR _signature IS NULL OR _signature_schema IS NULL OR _created_at_client IS NULL THEN
        RAISE EXCEPTION 'Operation payload is missing required fields';
    END IF;

    IF _signature_schema <> 'device-signature-v1' THEN
        RAISE EXCEPTION 'Unsupported signature_schema';
    END IF;

    IF _op_type NOT IN (
        'create', 'update', 'delete', 'restore', 'rekey',
        'add_member', 'remove_member', 'update_member_permission'
    ) THEN
        RAISE EXCEPTION 'Unsupported op_type';
    END IF;

    IF _record_type NOT IN (
        'collection_metadata', 'collection_member', 'collection_item',
        'collection_key', 'tombstone'
    ) THEN
        RAISE EXCEPTION 'Unsupported record_type';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = _actor_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Actor vault does not belong to caller';
    END IF;

    SELECT * INTO _existing_op
    FROM public.collection_operations
    WHERE op_id = _op_id;

    IF FOUND THEN
        IF _existing_op.op_hash <> _op_hash THEN
            RAISE EXCEPTION 'op_id reused with a different op_hash';
        END IF;
        IF _existing_op.actor_user_id <> _uid OR _existing_op.collection_id <> _collection_id THEN
            RAISE EXCEPTION 'op_id belongs to another caller';
        END IF;

        SELECT * INTO _head
        FROM public.collection_op_log_heads
        WHERE collection_id = _collection_id;

        RETURN jsonb_build_object(
            'applied', true,
            'idempotent', true,
            'op_id', _op_id,
            'sequence_number', _existing_op.sequence_number,
            'resulting_collection_head', _existing_op.resulting_collection_head,
            'current_head', _head.current_head,
            'current_sequence_number', _head.current_sequence_number,
            'conflict_reason', NULL
        );
    END IF;

    SELECT * INTO _head
    FROM public.collection_op_log_heads
    WHERE collection_id = _collection_id
    FOR UPDATE;

    IF NOT FOUND THEN
        IF _op_type <> 'create' OR _record_type <> 'collection_metadata' OR _base_collection_head IS NOT NULL THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'collection_not_found',
                'current_head', NULL,
                'current_sequence_number', 0
            );
        END IF;

        INSERT INTO public.collection_op_log_heads (
            collection_id, owner_user_id, current_head, current_op_id, current_sequence_number
        ) VALUES (
            _collection_id, _uid, NULL, NULL, 0
        )
        RETURNING * INTO _head;

        INSERT INTO public.collection_op_log_members (
            collection_id, user_id, permission, status, added_op_id
        ) VALUES (
            _collection_id, _uid, 'owner', 'active', _op_id
        );
    ELSE
        IF _base_collection_head IS NULL OR _head.current_head <> _base_collection_head THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_collection_head',
                'current_head', _head.current_head,
                'current_sequence_number', _head.current_sequence_number
            );
        END IF;

        IF NOT public.is_collection_op_log_editor(_collection_id, _uid) THEN
            RAISE EXCEPTION 'Collection edit permission required';
        END IF;
    END IF;

    _next_sequence := _head.current_sequence_number + 1;

    SELECT * INTO _existing_record
    FROM public.collection_records
    WHERE collection_id = _collection_id AND record_id = _record_id
    FOR UPDATE;
    _record_exists := FOUND;

    IF _record_exists AND _existing_record.record_type <> _record_type THEN
        RETURN jsonb_build_object(
            'applied', false,
            'conflict_reason', 'record_type_mismatch',
            'current_record_version', _existing_record.record_version,
            'current_head', _head.current_head,
            'current_sequence_number', _head.current_sequence_number
        );
    END IF;

    IF _op_type = 'create' THEN
        IF _record_exists AND NOT _existing_record.is_tombstone THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'record_already_exists',
                'current_record_version', _existing_record.record_version,
                'current_head', _head.current_head,
                'current_sequence_number', _head.current_sequence_number
            );
        END IF;
        IF _base_record_version IS NOT NULL OR _previous_ciphertext_hash IS NOT NULL THEN
            RETURN jsonb_build_object('applied', false, 'conflict_reason', 'create_must_not_carry_base');
        END IF;
    ELSE
        IF NOT _record_exists THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'record_not_found',
                'current_head', _head.current_head,
                'current_sequence_number', _head.current_sequence_number
            );
        END IF;
        IF _existing_record.record_version <> _base_record_version THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_record_version',
                'current_record_version', _existing_record.record_version,
                'current_head', _head.current_head,
                'current_sequence_number', _head.current_sequence_number
            );
        END IF;
        IF _existing_record.ciphertext_hash <> _previous_ciphertext_hash THEN
            RETURN jsonb_build_object(
                'applied', false,
                'conflict_reason', 'stale_previous_ciphertext_hash',
                'current_record_version', _existing_record.record_version,
                'current_head', _head.current_head,
                'current_sequence_number', _head.current_sequence_number
            );
        END IF;
    END IF;

    IF p_record_payload IS NULL THEN
        RAISE EXCEPTION 'record_payload is required';
    END IF;

    INSERT INTO public.collection_operations (
        op_id, op_hash, collection_id, actor_user_id, actor_vault_id,
        author_device_id, op_type, record_id, record_type,
        base_record_version, previous_ciphertext_hash, new_record_hash,
        base_collection_head, resulting_collection_head,
        payload_ciphertext_hash, payload_aad_hash,
        signed_body, signature, signature_schema, trust_epoch,
        created_at_client, sequence_number
    ) VALUES (
        _op_id, _op_hash, _collection_id, _uid, _actor_vault_id,
        _author_device_id, _op_type, _record_id, _record_type,
        _base_record_version, _previous_ciphertext_hash, _new_record_hash,
        _base_collection_head, _resulting_collection_head,
        _payload_ciphertext_hash, _payload_aad_hash,
        _signed_body, _signature, _signature_schema, _trust_epoch,
        _created_at_client, _next_sequence
    );

    INSERT INTO public.collection_records (
        collection_id, record_id, record_type, record_version, key_version,
        aad_hash, ciphertext_hash, nonce, ciphertext, last_op_id,
        last_op_hash, is_tombstone
    ) VALUES (
        _collection_id,
        _record_id,
        _record_type,
        COALESCE(_base_record_version, 0) + 1,
        (p_record_payload->>'key_version')::BIGINT,
        p_record_payload->>'aad_hash',
        p_record_payload->>'ciphertext_hash',
        p_record_payload->>'nonce',
        p_record_payload->>'ciphertext',
        _op_id,
        _op_hash,
        _op_type IN ('delete', 'remove_member')
    )
    ON CONFLICT (collection_id, record_id)
    DO UPDATE SET
        record_version = EXCLUDED.record_version,
        key_version = EXCLUDED.key_version,
        aad_hash = EXCLUDED.aad_hash,
        ciphertext_hash = EXCLUDED.ciphertext_hash,
        nonce = EXCLUDED.nonce,
        ciphertext = EXCLUDED.ciphertext,
        last_op_id = EXCLUDED.last_op_id,
        last_op_hash = EXCLUDED.last_op_hash,
        is_tombstone = EXCLUDED.is_tombstone,
        updated_at = NOW();

    _payload_kind := p_op->>'membership_kind';
    _target_user_id := NULLIF(p_op->>'target_user_id', '')::UUID;
    _target_permission := NULLIF(p_op->>'target_permission', '');

    IF p_key_envelope IS NOT NULL THEN
        _key_recipient_user_id := (p_key_envelope->>'recipient_user_id')::UUID;
        _key_version := (p_key_envelope->>'key_version')::BIGINT;
        _wrapped_key := p_key_envelope->>'wrapped_key';
        _pq_wrapped_key := p_key_envelope->>'pq_wrapped_key';

        IF _key_recipient_user_id IS NULL OR _key_version IS NULL
           OR _wrapped_key IS NULL OR _pq_wrapped_key IS NULL THEN
            RAISE EXCEPTION 'key envelope is missing required fields';
        END IF;

        IF _op_type = 'create' AND _record_type = 'collection_metadata' AND _key_recipient_user_id <> _uid THEN
            RAISE EXCEPTION 'collection create key envelope must target the caller';
        END IF;

        IF _op_type IN ('add_member', 'update_member_permission') AND _key_recipient_user_id <> _target_user_id THEN
            RAISE EXCEPTION 'member key envelope must target the affected member';
        END IF;

        INSERT INTO public.collection_op_log_key_envelopes (
            collection_id, user_id, key_version, wrapped_key, pq_wrapped_key, added_op_id
        ) VALUES (
            _collection_id, _key_recipient_user_id, _key_version, _wrapped_key, _pq_wrapped_key, _op_id
        )
        ON CONFLICT (collection_id, user_id, key_version)
        DO UPDATE SET
            wrapped_key = EXCLUDED.wrapped_key,
            pq_wrapped_key = EXCLUDED.pq_wrapped_key,
            added_op_id = EXCLUDED.added_op_id,
            revoked_op_id = NULL,
            updated_at = NOW();
    END IF;

    IF _op_type = 'add_member' THEN
        IF _target_user_id IS NULL OR _target_permission NOT IN ('view', 'edit') THEN
            RAISE EXCEPTION 'add_member requires target_user_id and target_permission';
        END IF;
        INSERT INTO public.collection_op_log_members (
            collection_id, user_id, permission, status, added_op_id
        ) VALUES (
            _collection_id, _target_user_id, _target_permission, 'active', _op_id
        )
        ON CONFLICT (collection_id, user_id)
        DO UPDATE SET
            permission = EXCLUDED.permission,
            status = 'active',
            added_op_id = EXCLUDED.added_op_id,
            removed_op_id = NULL,
            updated_at = NOW();
    ELSIF _op_type = 'remove_member' THEN
        IF _target_user_id IS NULL THEN
            RAISE EXCEPTION 'remove_member requires target_user_id';
        END IF;
        UPDATE public.collection_op_log_members
        SET status = 'removed',
            removed_op_id = _op_id,
            updated_at = NOW()
        WHERE collection_id = _collection_id
          AND user_id = _target_user_id
          AND permission <> 'owner';

        UPDATE public.collection_op_log_key_envelopes
        SET revoked_op_id = _op_id,
            updated_at = NOW()
        WHERE collection_id = _collection_id
          AND user_id = _target_user_id;
    ELSIF _op_type = 'update_member_permission' THEN
        IF _target_user_id IS NULL OR _target_permission NOT IN ('view', 'edit') THEN
            RAISE EXCEPTION 'update_member_permission requires target_user_id and target_permission';
        END IF;
        UPDATE public.collection_op_log_members
        SET permission = _target_permission,
            updated_at = NOW()
        WHERE collection_id = _collection_id
          AND user_id = _target_user_id
          AND status = 'active'
          AND permission <> 'owner';
    END IF;

    UPDATE public.collection_op_log_heads
    SET current_head = _resulting_collection_head,
        current_op_id = _op_id,
        current_sequence_number = _next_sequence,
        updated_at = NOW()
    WHERE collection_id = _collection_id;

    RETURN jsonb_build_object(
        'applied', true,
        'idempotent', false,
        'op_id', _op_id,
        'sequence_number', _next_sequence,
        'resulting_collection_head', _resulting_collection_head,
        'current_head', _resulting_collection_head,
        'current_sequence_number', _next_sequence,
        'conflict_reason', NULL
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.get_collection_head(p_collection_id UUID)
RETURNS TABLE (
    collection_id UUID,
    current_head TEXT,
    current_op_id UUID,
    current_sequence_number BIGINT,
    updated_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT h.collection_id, h.current_head, h.current_op_id,
           h.current_sequence_number, h.updated_at
    FROM public.collection_op_log_heads h
    WHERE h.collection_id = p_collection_id
      AND public.is_collection_op_log_active_member(p_collection_id, auth.uid());
$$;

CREATE OR REPLACE FUNCTION public.get_collection_changes_since(
    p_collection_id UUID,
    p_since_sequence BIGINT,
    p_limit INTEGER DEFAULT 500
)
RETURNS TABLE (
    op_id UUID,
    op_hash TEXT,
    collection_id UUID,
    actor_user_id UUID,
    actor_vault_id UUID,
    author_device_id UUID,
    op_type TEXT,
    record_id UUID,
    record_type TEXT,
    base_record_version BIGINT,
    previous_ciphertext_hash TEXT,
    new_record_hash TEXT,
    base_collection_head TEXT,
    resulting_collection_head TEXT,
    payload_ciphertext_hash TEXT,
    payload_aad_hash TEXT,
    signed_body JSONB,
    signature TEXT,
    signature_schema TEXT,
    trust_epoch BIGINT,
    created_at_client TIMESTAMPTZ,
    received_at_server TIMESTAMPTZ,
    sequence_number BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 500), 1), 1000);
BEGIN
    IF NOT public.is_collection_op_log_active_member(p_collection_id, auth.uid()) THEN
        RAISE EXCEPTION 'Collection access denied';
    END IF;

    RETURN QUERY
    SELECT o.op_id, o.op_hash, o.collection_id, o.actor_user_id,
           o.actor_vault_id, o.author_device_id, o.op_type,
           o.record_id, o.record_type, o.base_record_version,
           o.previous_ciphertext_hash, o.new_record_hash,
           o.base_collection_head, o.resulting_collection_head,
           o.payload_ciphertext_hash, o.payload_aad_hash,
           o.signed_body, o.signature, o.signature_schema,
           o.trust_epoch, o.created_at_client, o.received_at_server,
           o.sequence_number
    FROM public.collection_operations o
    WHERE o.collection_id = p_collection_id
      AND o.sequence_number > COALESCE(p_since_sequence, 0)
    ORDER BY o.sequence_number ASC
    LIMIT _limit;
END;
$$;

CREATE OR REPLACE FUNCTION public.get_collection_records_by_ids(
    p_collection_id UUID,
    p_record_ids UUID[]
)
RETURNS TABLE (
    collection_id UUID,
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
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT r.collection_id, r.record_id, r.record_type, r.record_version,
           r.key_version, r.aad_hash, r.ciphertext_hash, r.nonce,
           r.ciphertext, r.last_op_id, r.last_op_hash, r.is_tombstone,
           r.created_at, r.updated_at
    FROM public.collection_records r
    WHERE r.collection_id = p_collection_id
      AND r.record_id = ANY(p_record_ids)
      AND public.is_collection_op_log_active_member(p_collection_id, auth.uid());
$$;

CREATE OR REPLACE FUNCTION public.get_collection_author_trust_material(
    p_collection_id UUID,
    p_author_user_ids UUID[]
)
RETURNS TABLE (
    user_id UUID,
    vault_id UUID,
    device_id UUID,
    public_signing_key TEXT,
    trust_epoch BIGINT,
    status TEXT
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT v.user_id,
           d.vault_id,
           d.device_id,
           d.public_signing_key,
           d.trust_epoch,
           d.status
    FROM public.vault_device_trust_records d
    JOIN public.vaults v ON v.id = d.vault_id
    WHERE v.user_id = ANY(p_author_user_ids)
      AND public.is_collection_op_log_active_member(p_collection_id, auth.uid())
      AND public.is_collection_op_log_active_member(p_collection_id, v.user_id);
$$;

CREATE OR REPLACE FUNCTION public.get_collection_key_envelope(p_collection_id UUID)
RETURNS TABLE (
    collection_id UUID,
    user_id UUID,
    key_version BIGINT,
    wrapped_key TEXT,
    pq_wrapped_key TEXT,
    updated_at TIMESTAMPTZ
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT e.collection_id, e.user_id, e.key_version,
           e.wrapped_key, e.pq_wrapped_key, e.updated_at
    FROM public.collection_op_log_key_envelopes e
    WHERE e.collection_id = p_collection_id
      AND e.user_id = auth.uid()
      AND e.revoked_op_id IS NULL
      AND public.is_collection_op_log_active_member(p_collection_id, auth.uid())
    ORDER BY e.key_version DESC, e.updated_at DESC
    LIMIT 1;
$$;

REVOKE ALL ON FUNCTION public.submit_collection_operation(JSONB, JSONB, JSONB) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_collection_op_log_active_member(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.is_collection_op_log_editor(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_collection_head(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_collection_changes_since(UUID, BIGINT, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_collection_records_by_ids(UUID, UUID[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_collection_author_trust_material(UUID, UUID[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_collection_key_envelope(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.is_collection_op_log_active_member(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.is_collection_op_log_editor(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.submit_collection_operation(JSONB, JSONB, JSONB) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_collection_head(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_collection_changes_since(UUID, BIGINT, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_collection_records_by_ids(UUID, UUID[]) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_collection_author_trust_material(UUID, UUID[]) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_collection_key_envelope(UUID) TO authenticated;
