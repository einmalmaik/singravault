-- Avoid PL/pgSQL ambiguity between the RETURNS TABLE output parameter
-- `user_id` and the user_opaque_records.user_id column.

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
    ON CONFLICT ON CONSTRAINT user_opaque_records_user_id_key DO UPDATE
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
REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role;

COMMENT ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) IS
    'Atomically consumes authorized reset state, writes the new OPAQUE record, clears GoTrue password login, revokes sessions, and cleans reset state.';
