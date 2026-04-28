-- Supabase Storage blocks direct writes to storage.objects from application RPCs.
-- Account deletion keeps the authoritative DB cleanup in this RPC, while the
-- account-delete Edge Function removes vault-attachments objects via Storage API.

CREATE OR REPLACE FUNCTION public.delete_my_account(
    p_two_factor_challenge_id UUID DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $delete_my_account$
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
              AND method = 'totp'
              AND verified_at IS NOT NULL
              AND consumed_at IS NOT NULL
              AND consumed_at > NOW() - INTERVAL '5 minutes'
        ) THEN
            RAISE EXCEPTION 'ACCOUNT_DELETE_2FA_REQUIRED';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(_uid::TEXT, 0));

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
$delete_my_account$;

REVOKE ALL ON FUNCTION public.delete_my_account(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_my_account(UUID) TO authenticated;
