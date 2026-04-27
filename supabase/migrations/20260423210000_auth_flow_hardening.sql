-- Harden account recovery and auth throttling.

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
            'recovery_verify',
            'totp_verify',
            'backup_code_verify',
            'opaque_login'
        )
    );

CREATE INDEX IF NOT EXISTS idx_rate_limit_ip_action_attempted_at
    ON public.rate_limit_attempts(ip_address, action, attempted_at)
    WHERE ip_address IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.password_reset_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_password_reset_challenges_user_expires_at
    ON public.password_reset_challenges(user_id, expires_at);

CREATE INDEX IF NOT EXISTS idx_password_reset_challenges_token_active
    ON public.password_reset_challenges(token_hash)
    WHERE used_at IS NULL;

ALTER TABLE public.password_reset_challenges ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.password_reset_challenges FROM PUBLIC;
REVOKE ALL ON TABLE public.password_reset_challenges FROM anon;
REVOKE ALL ON TABLE public.password_reset_challenges FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.password_reset_challenges TO service_role;

COMMENT ON TABLE public.password_reset_challenges IS
    'Short-lived reset-scoped tokens created after recovery-code verification. These never grant an app session.';

CREATE OR REPLACE FUNCTION public.revoke_user_auth_sessions(
    p_user_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _refresh_tokens_user_id_type TEXT;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'Invalid user id';
    END IF;

    SELECT udt_name
    INTO _refresh_tokens_user_id_type
    FROM information_schema.columns
    WHERE table_schema = 'auth'
      AND table_name = 'refresh_tokens'
      AND column_name = 'user_id';

    IF _refresh_tokens_user_id_type = 'uuid' THEN
        EXECUTE
            'UPDATE auth.refresh_tokens
             SET revoked = TRUE, updated_at = NOW()
             WHERE user_id = $1 AND revoked = FALSE'
        USING p_user_id;
    ELSE
        EXECUTE
            'UPDATE auth.refresh_tokens
             SET revoked = TRUE, updated_at = NOW()
             WHERE user_id = $1::TEXT AND revoked = FALSE'
        USING p_user_id;
    END IF;

    DELETE FROM auth.sessions
    WHERE user_id = p_user_id;
END;
$$;

REVOKE ALL ON FUNCTION public.revoke_user_auth_sessions(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.revoke_user_auth_sessions(UUID) TO service_role;

COMMENT ON FUNCTION public.revoke_user_auth_sessions(UUID) IS
    'Revokes all GoTrue refresh tokens and sessions for the target user after a password reset.';
