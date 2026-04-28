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
AS $record_auth_rate_limit_failure_atomic$
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
$record_auth_rate_limit_failure_atomic$;
