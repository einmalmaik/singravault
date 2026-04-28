-- Fix linked-database lint errors found during the final ZK hardening pass.
-- These changes are non-destructive and keep existing auth/reset semantics.

CREATE OR REPLACE FUNCTION public.rotate_totp_encryption_key(
    p_new_key TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private, extensions
AS $$
DECLARE
    _old_key TEXT;
    _rotated_count INTEGER := 0;
BEGIN
    IF p_new_key IS NULL OR length(trim(p_new_key)) = 0 THEN
        RAISE EXCEPTION 'New key must not be empty';
    END IF;

    IF p_new_key !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid key format: expected 64 hex chars';
    END IF;

    SELECT value INTO _old_key
    FROM private.app_secrets
    WHERE name = 'totp_encryption_key'
    LIMIT 1;

    IF _old_key IS NULL THEN
        RAISE EXCEPTION 'Missing secret private.app_secrets(totp_encryption_key)';
    END IF;

    IF lower(_old_key) = lower(p_new_key) THEN
        RAISE EXCEPTION 'New key equals current key';
    END IF;

    UPDATE public.user_2fa
    SET totp_secret_enc = encode(
        extensions.pgp_sym_encrypt(
            extensions.pgp_sym_decrypt(decode(totp_secret_enc, 'base64'), _old_key),
            p_new_key,
            'cipher-algo=aes256, compress-algo=1'::text
        ),
        'base64'
    )
    WHERE totp_secret_enc IS NOT NULL;

    GET DIAGNOSTICS _rotated_count = ROW_COUNT;

    UPDATE private.app_secrets
    SET value = lower(p_new_key)
    WHERE name = 'totp_encryption_key';

    RETURN _rotated_count;
END;
$$;

REVOKE ALL ON FUNCTION public.rotate_totp_encryption_key(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.rotate_totp_encryption_key(TEXT) TO service_role;

CREATE OR REPLACE FUNCTION public.revoke_user_auth_sessions(
    p_user_id UUID
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'Invalid user id';
    END IF;

    -- GoTrue has used both uuid and varchar user_id columns across versions.
    -- Casting the column to text keeps this revocation path lint-clean and
    -- compatible with both layouts.
    UPDATE auth.refresh_tokens
    SET revoked = TRUE, updated_at = NOW()
    WHERE user_id::TEXT = p_user_id::TEXT
      AND revoked = FALSE;

    DELETE FROM auth.sessions
    WHERE user_id = p_user_id;
END;
$$;

REVOKE ALL ON FUNCTION public.revoke_user_auth_sessions(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.revoke_user_auth_sessions(UUID) TO service_role;

CREATE OR REPLACE FUNCTION public.finish_opaque_password_reset(
    p_challenge_id UUID,
    p_reset_state_id UUID,
    p_registration_record TEXT
)
RETURNS TABLE(user_id UUID, email TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $finish_opaque_password_reset$
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
    FROM public.opaque_password_reset_states reset_states
    WHERE reset_states.id = p_reset_state_id
      AND reset_states.user_id = v_challenge.user_id
      AND LOWER(TRIM(reset_states.email)) = LOWER(TRIM(v_challenge.email))
      AND reset_states.consumed_at IS NULL
      AND reset_states.expires_at > v_now
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
$finish_opaque_password_reset$;

REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role;

COMMENT ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) IS
    'Atomically consumes authorized reset state, writes the new OPAQUE record, clears GoTrue password login, revokes sessions, and cleans reset state.';
