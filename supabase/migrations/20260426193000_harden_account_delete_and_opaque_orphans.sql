-- Harden account deletion and prevent orphaned OPAQUE records.

-- Existing deployments may already contain orphaned records from auth.users
-- deletion. Clean them before adding defensive foreign keys.
DELETE FROM public.user_opaque_records records
WHERE NOT EXISTS (
    SELECT 1 FROM auth.users users WHERE users.id = records.user_id
);

DELETE FROM public.opaque_login_states states
WHERE NOT EXISTS (
    SELECT 1 FROM auth.users users WHERE users.id = states.user_id
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'user_opaque_records_user_id_fkey'
          AND conrelid = 'public.user_opaque_records'::regclass
    ) THEN
        ALTER TABLE public.user_opaque_records
            ADD CONSTRAINT user_opaque_records_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'opaque_login_states_user_id_fkey'
          AND conrelid = 'public.opaque_login_states'::regclass
    ) THEN
        ALTER TABLE public.opaque_login_states
            ADD CONSTRAINT opaque_login_states_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
    END IF;
END;
$$;

DROP FUNCTION IF EXISTS public.delete_my_account();

CREATE OR REPLACE FUNCTION public.delete_my_account(
    p_two_factor_challenge_id UUID DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth, storage
AS $$
DECLARE
    _uid UUID := auth.uid();
    _jwt jsonb := auth.jwt();
    _iat_text TEXT;
    _iat BIGINT;
    _now_epoch BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
    _email TEXT;
    _deleted_auth_rows INTEGER := 0;
    _remaining jsonb := '{}'::jsonb;
    _count BIGINT := 0;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'AUTH_REQUIRED';
    END IF;

    SELECT LOWER(TRIM(email::TEXT))
      INTO _email
      FROM auth.users
     WHERE id = _uid;

    IF _email IS NULL THEN
        RAISE EXCEPTION 'AUTH_REQUIRED';
    END IF;

    _iat_text := _jwt ->> 'iat';
    IF _iat_text IS NULL OR _iat_text !~ '^\d+$' THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    _iat := _iat_text::BIGINT;
    IF (_now_epoch - _iat) > 300 THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.user_2fa
        WHERE user_id = _uid
          AND COALESCE(is_enabled, false) = true
    ) THEN
        IF p_two_factor_challenge_id IS NULL OR NOT EXISTS (
            SELECT 1
            FROM public.two_factor_challenges
            WHERE id = p_two_factor_challenge_id
              AND user_id = _uid
              AND purpose = 'critical_action'
              AND verified_at IS NOT NULL
              AND consumed_at IS NOT NULL
              AND consumed_at > NOW() - INTERVAL '5 minutes'
        ) THEN
            RAISE EXCEPTION 'ACCOUNT_DELETE_2FA_REQUIRED';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(_uid::TEXT, 0));

    -- Explicit cleanup covers non-cascading and email-address scoped state.
    DELETE FROM public.vault_item_tags
    WHERE vault_item_id IN (SELECT id FROM public.vault_items WHERE user_id = _uid)
       OR tag_id IN (SELECT id FROM public.tags WHERE user_id = _uid);

    IF to_regclass('public.shared_collection_items') IS NOT NULL THEN
        DELETE FROM public.shared_collection_items
        WHERE vault_item_id IN (SELECT id FROM public.vault_items WHERE user_id = _uid)
           OR collection_id IN (SELECT id FROM public.shared_collections WHERE owner_id = _uid)
           OR added_by = _uid;
    END IF;

    IF to_regclass('public.collection_keys') IS NOT NULL THEN
        DELETE FROM public.collection_keys
        WHERE user_id = _uid
           OR collection_id IN (SELECT id FROM public.shared_collections WHERE owner_id = _uid);
    END IF;

    IF to_regclass('public.collection_audit_log') IS NOT NULL THEN
        DELETE FROM public.collection_audit_log
        WHERE user_id = _uid
           OR collection_id IN (SELECT id FROM public.shared_collections WHERE owner_id = _uid);
    END IF;

    IF to_regclass('public.file_attachments') IS NOT NULL THEN
        DELETE FROM public.file_attachments WHERE user_id = _uid;
    END IF;

    IF to_regclass('storage.objects') IS NOT NULL THEN
        DELETE FROM storage.objects
        WHERE bucket_id = 'vault-attachments'
          AND name LIKE _uid::TEXT || '/%';
    END IF;

    DELETE FROM public.vault_items WHERE user_id = _uid;
    DELETE FROM public.categories WHERE user_id = _uid;
    DELETE FROM public.tags WHERE user_id = _uid;
    DELETE FROM public.vaults WHERE user_id = _uid;

    IF to_regclass('public.emergency_access') IS NOT NULL THEN
        DELETE FROM public.emergency_access WHERE grantor_id = _uid;
        UPDATE public.emergency_access
           SET trusted_user_id = NULL,
               updated_at = NOW()
         WHERE trusted_user_id = _uid;
    END IF;

    IF to_regclass('public.family_members') IS NOT NULL THEN
        DELETE FROM public.family_members
        WHERE family_owner_id = _uid OR member_user_id = _uid;
    END IF;

    IF to_regclass('public.shared_collection_members') IS NOT NULL THEN
        DELETE FROM public.shared_collection_members WHERE user_id = _uid;
    END IF;

    IF to_regclass('public.shared_collections') IS NOT NULL THEN
        DELETE FROM public.shared_collections WHERE owner_id = _uid;
    END IF;

    IF to_regclass('public.support_tickets') IS NOT NULL THEN
        DELETE FROM public.support_tickets WHERE user_id = _uid;
    END IF;

    IF to_regclass('public.support_messages') IS NOT NULL THEN
        UPDATE public.support_messages SET author_user_id = NULL WHERE author_user_id = _uid;
    END IF;

    IF to_regclass('public.support_events') IS NOT NULL THEN
        UPDATE public.support_events SET actor_user_id = NULL WHERE actor_user_id = _uid;
    END IF;

    IF to_regclass('public.team_access_audit_log') IS NOT NULL THEN
        UPDATE public.team_access_audit_log
           SET actor_user_id = NULL
         WHERE actor_user_id = _uid;
        UPDATE public.team_access_audit_log
           SET target_user_id = NULL
         WHERE target_user_id = _uid;
    END IF;

    DELETE FROM public.opaque_registration_challenges
    WHERE user_id = _uid OR LOWER(TRIM(email)) = _email;
    DELETE FROM public.recovery_tokens
    WHERE LOWER(TRIM(email)) = _email;
    DELETE FROM public.user_opaque_records WHERE user_id = _uid OR opaque_identifier = _email;
    DELETE FROM public.opaque_login_states WHERE user_id = _uid OR opaque_identifier = _email;
    DELETE FROM public.opaque_password_reset_states WHERE user_id = _uid OR LOWER(TRIM(email)) = _email;
    DELETE FROM public.opaque_reenrollment_required WHERE user_id = _uid OR LOWER(TRIM(email)) = _email;
    DELETE FROM public.password_reset_challenges WHERE user_id = _uid;
    DELETE FROM public.two_factor_challenges WHERE user_id = _uid;
    DELETE FROM public.sensitive_action_challenges WHERE user_id = _uid;
    DELETE FROM public.webauthn_challenges WHERE user_id = _uid;
    DELETE FROM public.passkey_credentials WHERE user_id = _uid;
    DELETE FROM public.backup_codes WHERE user_id = _uid;
    DELETE FROM public.user_2fa WHERE user_id = _uid;
    DELETE FROM public.user_security WHERE id = _uid;
    DELETE FROM public.user_keys WHERE user_id = _uid;
    DELETE FROM public.user_roles WHERE user_id = _uid;
    DELETE FROM public.subscriptions WHERE user_id = _uid;
    DELETE FROM public.profiles WHERE user_id = _uid;

    DELETE FROM auth.users WHERE id = _uid;
    GET DIAGNOSTICS _deleted_auth_rows = ROW_COUNT;

    IF _deleted_auth_rows = 0 THEN
        RAISE EXCEPTION 'AUTH_USER_DELETE_FAILED';
    END IF;

    SELECT COUNT(*) INTO _count FROM public.profiles WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('profiles', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.vaults WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('vaults', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.vault_items WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('vault_items', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.categories WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('categories', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.tags WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('tags', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.user_roles WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('user_roles', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.user_opaque_records WHERE user_id = _uid OR opaque_identifier = _email;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('user_opaque_records', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.opaque_login_states WHERE user_id = _uid OR opaque_identifier = _email;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('opaque_login_states', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.user_2fa WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('user_2fa', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.backup_codes WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('backup_codes', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.passkey_credentials WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('passkey_credentials', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.user_keys WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('user_keys', _count); END IF;
    SELECT COUNT(*) INTO _count FROM public.subscriptions WHERE user_id = _uid;
    IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('subscriptions', _count); END IF;

    IF to_regclass('public.file_attachments') IS NOT NULL THEN
        EXECUTE 'SELECT COUNT(*) FROM public.file_attachments WHERE user_id = $1' INTO _count USING _uid;
        IF _count > 0 THEN _remaining := _remaining || jsonb_build_object('file_attachments', _count); END IF;
    END IF;

    IF _remaining <> '{}'::jsonb THEN
        RAISE EXCEPTION 'ACCOUNT_DELETE_INCOMPLETE:%', _remaining::TEXT;
    END IF;

    RETURN jsonb_build_object('deleted', true, 'user_id', _uid);
END;
$$;

REVOKE ALL ON FUNCTION public.delete_my_account(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_my_account(UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.finish_opaque_password_reset(
    p_challenge_id UUID,
    p_reset_state_id UUID,
    p_registration_record TEXT
)
RETURNS TABLE (user_id UUID, email TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    v_now TIMESTAMPTZ := NOW();
    v_challenge public.password_reset_challenges%ROWTYPE;
    v_reset_state public.opaque_password_reset_states%ROWTYPE;
    v_identifier TEXT;
BEGIN
    IF p_challenge_id IS NULL OR p_reset_state_id IS NULL OR p_registration_record IS NULL OR p_registration_record = '' THEN
        RAISE EXCEPTION 'Invalid OPAQUE reset finish payload';
    END IF;

    SELECT *
    INTO v_challenge
    FROM public.password_reset_challenges
    WHERE id = p_challenge_id
      AND used_at IS NULL
      AND expires_at > v_now
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid or expired reset challenge';
    END IF;

    IF v_challenge.authorized_at IS NULL THEN
        RAISE EXCEPTION 'Reset challenge is not authorized';
    END IF;

    IF v_challenge.two_factor_required AND v_challenge.two_factor_verified_at IS NULL THEN
        RAISE EXCEPTION 'Two-factor verification required';
    END IF;

    SELECT *
    INTO v_reset_state
    FROM public.opaque_password_reset_states
    WHERE id = p_reset_state_id
      AND user_id = v_challenge.user_id
      AND LOWER(TRIM(email)) = LOWER(TRIM(v_challenge.email))
      AND consumed_at IS NULL
      AND expires_at > v_now
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invalid or expired OPAQUE reset state';
    END IF;

    v_identifier := LOWER(TRIM(v_reset_state.email));

    IF EXISTS (
        SELECT 1
        FROM public.user_opaque_records records
        WHERE records.opaque_identifier = v_identifier
          AND records.user_id <> v_challenge.user_id
    ) THEN
        RAISE EXCEPTION 'OPAQUE_RECORD_CONFLICT';
    END IF;

    UPDATE public.password_reset_challenges
    SET used_at = v_now
    WHERE id = v_challenge.id;

    UPDATE public.opaque_password_reset_states
    SET consumed_at = v_now
    WHERE id = v_reset_state.id;

    INSERT INTO public.user_opaque_records (
        user_id,
        opaque_identifier,
        registration_record,
        updated_at
    )
    VALUES (
        v_challenge.user_id,
        v_identifier,
        p_registration_record,
        v_now
    )
    ON CONFLICT (user_id) DO UPDATE
    SET opaque_identifier = EXCLUDED.opaque_identifier,
        registration_record = EXCLUDED.registration_record,
        updated_at = EXCLUDED.updated_at;

    UPDATE auth.users
    SET encrypted_password = NULL,
        updated_at = v_now
    WHERE id = v_challenge.user_id;

    PERFORM public.revoke_user_auth_sessions(v_challenge.user_id);

    UPDATE public.profiles
    SET auth_protocol = 'opaque'
    WHERE profiles.user_id = v_challenge.user_id;

    DELETE FROM public.user_security
    WHERE id = v_challenge.user_id;

    DELETE FROM public.password_reset_challenges
    WHERE password_reset_challenges.user_id = v_challenge.user_id
      AND password_reset_challenges.id <> v_challenge.id;

    DELETE FROM public.opaque_password_reset_states
    WHERE opaque_password_reset_states.user_id = v_challenge.user_id
      AND opaque_password_reset_states.id <> v_reset_state.id;

    user_id := v_challenge.user_id;
    email := v_identifier;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role;
