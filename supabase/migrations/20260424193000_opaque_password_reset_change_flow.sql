-- Harden OPAQUE account password reset/change flows.

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
            'opaque_reset'
        )
    );

ALTER TABLE public.recovery_tokens
    ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'forgot',
    ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ;

ALTER TABLE public.recovery_tokens
    DROP CONSTRAINT IF EXISTS recovery_tokens_purpose_check;

ALTER TABLE public.recovery_tokens
    ADD CONSTRAINT recovery_tokens_purpose_check
    CHECK (purpose IN ('forgot', 'change'));

CREATE INDEX IF NOT EXISTS idx_recovery_tokens_active_purpose
    ON public.recovery_tokens(email, purpose, expires_at)
    WHERE used_at IS NULL;

COMMENT ON COLUMN public.recovery_tokens.purpose IS
    'Reset entry point: forgot-password before login or password-change while authenticated.';

COMMENT ON COLUMN public.recovery_tokens.used_at IS
    'Set atomically when an email code is consumed; prevents replay.';

ALTER TABLE public.password_reset_challenges
    ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'forgot',
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS two_factor_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS two_factor_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS authorized_at TIMESTAMPTZ;

ALTER TABLE public.password_reset_challenges
    DROP CONSTRAINT IF EXISTS password_reset_challenges_purpose_check;

ALTER TABLE public.password_reset_challenges
    ADD CONSTRAINT password_reset_challenges_purpose_check
    CHECK (purpose IN ('forgot', 'change'));

CREATE INDEX IF NOT EXISTS idx_password_reset_challenges_authorized
    ON public.password_reset_challenges(user_id, authorized_at, expires_at)
    WHERE used_at IS NULL;

COMMENT ON COLUMN public.password_reset_challenges.authorized_at IS
    'Set only after email-code verification and, when required, successful 2FA/recovery-code verification.';

COMMENT ON COLUMN public.password_reset_challenges.two_factor_required IS
    'True when account 2FA was enabled at reset authorization time.';

CREATE OR REPLACE FUNCTION public.enforce_opaque_no_gotrue_password()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
  -- App-owned passwords are OPAQUE-only. Direct GoTrue password writes,
  -- including supabase.auth.updateUser({ password }), must not recreate a
  -- password verifier that could bypass OPAQUE.
  IF NEW.encrypted_password IS NOT NULL THEN
    NEW.encrypted_password = NULL;
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_opaque_no_gotrue_password_on_auth_users ON auth.users;

CREATE TRIGGER enforce_opaque_no_gotrue_password_on_auth_users
    BEFORE INSERT OR UPDATE OF encrypted_password ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_opaque_no_gotrue_password();

COMMENT ON FUNCTION public.enforce_opaque_no_gotrue_password() IS
    'Hard-blocks direct GoTrue password verifier creation; app-owned passwords must be enrolled through OPAQUE reset/registration.';

UPDATE auth.users
SET encrypted_password = NULL,
    updated_at = NOW()
WHERE encrypted_password IS NOT NULL;
