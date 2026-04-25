-- Follow-up hardening for OPAQUE auth/reset, rate limits, and migration auditability.

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
            'opaque_login',
            'opaque_reset',
            'opaque_register'
        )
    );

CREATE TABLE IF NOT EXISTS public.opaque_reenrollment_required (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT 'gotrue_password_without_opaque_record',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.opaque_reenrollment_required ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.opaque_reenrollment_required FROM PUBLIC;
REVOKE ALL ON TABLE public.opaque_reenrollment_required FROM anon;
REVOKE ALL ON TABLE public.opaque_reenrollment_required FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.opaque_reenrollment_required TO service_role;

COMMENT ON TABLE public.opaque_reenrollment_required IS
    'Service-role audit list for pre-cutover email/password users that must re-enroll through OPAQUE reset because their GoTrue verifier cannot be migrated without handling the password server-side.';

CREATE OR REPLACE FUNCTION public.record_auth_rate_limit_failure_atomic(
    p_identifier TEXT,
    p_action TEXT,
    p_ip_address TEXT,
    p_window_ms INTEGER,
    p_lockout_ms INTEGER,
    p_max_attempts INTEGER
)
RETURNS TABLE (failure_count INTEGER, locked_until TIMESTAMPTZ)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_now TIMESTAMPTZ := NOW();
    v_window_start TIMESTAMPTZ := v_now - (p_window_ms::TEXT || ' milliseconds')::INTERVAL;
    v_inserted_id UUID;
    v_account_failures INTEGER := 0;
    v_ip_failures INTEGER := 0;
    v_failure_count INTEGER := 0;
    v_locked_until TIMESTAMPTZ := NULL;
BEGIN
    IF p_identifier IS NULL OR p_identifier = '' OR p_action IS NULL OR p_action = '' THEN
        RAISE EXCEPTION 'Invalid rate-limit key';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('auth-rate-limit:identifier:' || p_action || ':' || p_identifier));
    IF p_ip_address IS NOT NULL AND p_ip_address <> '' THEN
        PERFORM pg_advisory_xact_lock(hashtext('auth-rate-limit:ip:' || p_action || ':' || p_ip_address));
    END IF;

    SELECT MAX(attempts.locked_until)
    INTO v_locked_until
    FROM public.rate_limit_attempts AS attempts
    WHERE attempts.action = p_action
      AND attempts.locked_until > v_now
      AND (
        attempts.identifier = p_identifier
        OR (p_ip_address IS NOT NULL AND attempts.ip_address = p_ip_address)
      );

    INSERT INTO public.rate_limit_attempts (
        identifier,
        action,
        success,
        attempted_at,
        locked_until,
        ip_address
    )
    VALUES (
        p_identifier,
        p_action,
        FALSE,
        v_now,
        NULL,
        p_ip_address
    )
    RETURNING id INTO v_inserted_id;

    SELECT COUNT(*)::INTEGER
    INTO v_account_failures
    FROM public.rate_limit_attempts AS attempts
    WHERE attempts.identifier = p_identifier
      AND attempts.action = p_action
      AND attempts.success = FALSE
      AND attempts.attempted_at >= v_window_start;

    IF p_ip_address IS NOT NULL AND p_ip_address <> '' THEN
        SELECT COUNT(*)::INTEGER
        INTO v_ip_failures
        FROM public.rate_limit_attempts AS attempts
        WHERE attempts.ip_address = p_ip_address
          AND attempts.action = p_action
          AND attempts.success = FALSE
          AND attempts.attempted_at >= v_window_start;
    END IF;

    v_failure_count := GREATEST(v_account_failures, v_ip_failures);

    IF v_locked_until IS NULL AND v_failure_count >= p_max_attempts THEN
        v_locked_until := v_now + (p_lockout_ms::TEXT || ' milliseconds')::INTERVAL;
    END IF;

    IF v_locked_until IS NOT NULL THEN
        UPDATE public.rate_limit_attempts
        SET locked_until = v_locked_until
        WHERE id = v_inserted_id;
    END IF;

    failure_count := v_failure_count;
    locked_until := v_locked_until;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) TO service_role;

COMMENT ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) IS
    'Records an auth failure under advisory locks and returns the post-insert failure count and lockout in one transaction.';

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
        LOWER(TRIM(v_reset_state.email)),
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
    email := LOWER(TRIM(v_reset_state.email));
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role;

COMMENT ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) IS
    'Atomically consumes authorized reset state, writes the new OPAQUE record, clears GoTrue password login, revokes sessions, and cleans reset state.';
