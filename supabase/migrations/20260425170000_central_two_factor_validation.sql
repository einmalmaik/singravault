-- Central server-side 2FA/VaultFA validation support.

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

CREATE TABLE IF NOT EXISTS public.two_factor_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (
        purpose IN (
            'account_login',
            'password_reset',
            'password_change',
            'account_security_change',
            'disable_2fa',
            'vault_unlock',
            'critical_action'
        )
    ),
    method TEXT CHECK (method IN ('totp', 'backup_code')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

ALTER TABLE public.two_factor_challenges ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.two_factor_challenges FROM PUBLIC;
REVOKE ALL ON TABLE public.two_factor_challenges FROM anon;
REVOKE ALL ON TABLE public.two_factor_challenges FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.two_factor_challenges TO service_role;

CREATE INDEX IF NOT EXISTS idx_two_factor_challenges_user_purpose_active
    ON public.two_factor_challenges(user_id, purpose, expires_at)
    WHERE consumed_at IS NULL;

COMMENT ON TABLE public.two_factor_challenges IS
    'Short-lived server-side challenge state for 2FA/VaultFA verification. The client never writes this table directly.';

COMMENT ON COLUMN public.two_factor_challenges.purpose IS
    'Binds a 2FA challenge to a single purpose so login/reset/vault/disable states cannot be reused across flows.';
