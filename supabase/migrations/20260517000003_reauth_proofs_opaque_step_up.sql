-- Replace the JWT iat-based freshness signal with a server-issued OPAQUE
-- reauth proof for all sensitive-action challenge issuance.
--
-- Problem with the previous approach:
--   issue_sensitive_action_challenge called require_recent_reauthentication(300),
--   which checks auth.jwt()->'iat'. A silent session refresh (refreshSession API)
--   mints a new JWT with a fresh iat without requiring any credential verification,
--   so an attacker with a live stolen session could: refresh → get fresh iat →
--   call begin_account_delete_challenge() → call delete_my_account() — all without
--   ever proving knowledge of the account password or any other credential.
--
-- Fix:
--   1. reauth_proofs table records successful OPAQUE credential verifications.
--      Only the service-role key (held by the auth-opaque Edge Function) can
--      insert rows; authenticated users can only consume their own proofs.
--   2. consume_reauth_proof(UUID) validates the proof atomically: checks it
--      belongs to auth.uid(), is not consumed, and is not expired, then marks it
--      consumed so it cannot be reused.
--   3. issue_sensitive_action_challenge now takes p_reauth_proof_id UUID and
--      calls consume_reauth_proof instead of require_recent_reauthentication.
--      A challenge can only be issued when the caller holds a proof that was
--      inserted by the OPAQUE server after a cryptographically verified login.
--   4. The old 2-argument overload of issue_sensitive_action_challenge, the
--      old no-argument begin_vault_reset_recovery(), the old no-argument
--      begin_account_delete_challenge(), and the old one-argument
--      delete_my_account(UUID) are all dropped to eliminate legacy bypass paths.

-- ============================================================
-- 1. reauth_proofs table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.reauth_proofs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes',
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_reauth_proofs_user_expires
    ON public.reauth_proofs (user_id, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE public.reauth_proofs ENABLE ROW LEVEL SECURITY;

-- No RLS policies for authenticated users: the table is written exclusively by
-- the service-role key (Edge Function) and read/updated only by SECURITY
-- DEFINER functions below.  Authenticated users have no direct table access.
REVOKE ALL ON TABLE public.reauth_proofs FROM PUBLIC;
REVOKE ALL ON TABLE public.reauth_proofs FROM anon;
REVOKE ALL ON TABLE public.reauth_proofs FROM authenticated;

COMMENT ON TABLE public.reauth_proofs IS
    'Short-lived, one-time records of successful OPAQUE credential verifications '
    'issued by the auth-opaque Edge Function. Used to gate sensitive-action '
    'challenge issuance so that a bare session refresh cannot satisfy the step-up '
    'requirement.';

-- ============================================================
-- 2. consume_reauth_proof — validate and atomically consume a proof
-- ============================================================

CREATE OR REPLACE FUNCTION public.consume_reauth_proof(
    p_proof_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid         UUID := auth.uid();
    _consumed_at TIMESTAMPTZ;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_proof_id IS NULL THEN
        RAISE EXCEPTION 'REAUTH_PROOF_REQUIRED';
    END IF;

    -- Opportunistically remove expired proofs for this user.
    DELETE FROM public.reauth_proofs
     WHERE user_id = _uid
       AND expires_at <= NOW();

    -- Atomically mark the proof consumed.
    UPDATE public.reauth_proofs
       SET consumed_at = NOW()
     WHERE id          = p_proof_id
       AND user_id     = _uid
       AND consumed_at IS NULL
       AND expires_at  > NOW()
    RETURNING consumed_at INTO _consumed_at;

    IF _consumed_at IS NULL THEN
        RAISE EXCEPTION 'REAUTH_PROOF_REQUIRED';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_reauth_proof(UUID) FROM PUBLIC;

COMMENT ON FUNCTION public.consume_reauth_proof(UUID) IS
    'Validates and atomically consumes an OPAQUE reauth proof for the current '
    'user. Raises REAUTH_PROOF_REQUIRED when the proof is missing, expired, '
    'already consumed, or belongs to a different user.';

-- ============================================================
-- 3. Replace issue_sensitive_action_challenge with a 3-arg version
--    that requires and consumes a real OPAQUE reauth proof.
-- ============================================================

-- Drop the old 2-argument overload that gated on JWT iat only.
DROP FUNCTION IF EXISTS public.issue_sensitive_action_challenge(TEXT, INTEGER);

CREATE OR REPLACE FUNCTION public.issue_sensitive_action_challenge(
    p_action        TEXT,
    p_ttl_seconds   INTEGER DEFAULT 300,
    p_reauth_proof_id UUID    DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid          UUID := auth.uid();
    _challenge_id UUID := gen_random_uuid();
    _expires_at   TIMESTAMPTZ;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    -- Require a valid, unconsumed OPAQUE reauth proof.
    -- consume_reauth_proof raises REAUTH_PROOF_REQUIRED if validation fails.
    PERFORM public.consume_reauth_proof(p_reauth_proof_id);

    IF p_action IS NULL OR btrim(p_action) = '' THEN
        RAISE EXCEPTION 'Invalid sensitive action';
    END IF;

    IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 OR p_ttl_seconds > 900 THEN
        RAISE EXCEPTION 'Invalid challenge ttl';
    END IF;

    -- Remove any stale challenges for this user and action.
    DELETE FROM public.sensitive_action_challenges
     WHERE user_id = _uid
       AND (action = p_action OR expires_at <= NOW());

    _expires_at := NOW() + make_interval(secs => p_ttl_seconds);

    INSERT INTO public.sensitive_action_challenges (id, user_id, action, expires_at)
    VALUES (_challenge_id, _uid, p_action, _expires_at);

    RETURN jsonb_build_object(
        'challenge_id', _challenge_id,
        'action',       p_action,
        'expires_at',   _expires_at
    );
END;
$$;

REVOKE ALL ON FUNCTION public.issue_sensitive_action_challenge(TEXT, INTEGER, UUID) FROM PUBLIC;

COMMENT ON FUNCTION public.issue_sensitive_action_challenge(TEXT, INTEGER, UUID) IS
    'Creates a short-lived, one-time sensitive-action challenge after consuming a '
    'valid OPAQUE reauth proof. The proof is consumed atomically and cannot be '
    'reused; a silent session refresh cannot produce a proof.';

-- ============================================================
-- 4. begin_vault_reset_recovery — now requires a reauth proof
-- ============================================================

-- Drop the old no-argument version that used iat freshness.
DROP FUNCTION IF EXISTS public.begin_vault_reset_recovery();

CREATE OR REPLACE FUNCTION public.begin_vault_reset_recovery(
    p_reauth_proof_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    RETURN public.issue_sensitive_action_challenge('vault_reset_recovery', 300, p_reauth_proof_id);
END;
$$;

REVOKE ALL ON FUNCTION public.begin_vault_reset_recovery(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.begin_vault_reset_recovery(UUID) TO authenticated;

COMMENT ON FUNCTION public.begin_vault_reset_recovery(UUID) IS
    'Starts the short-lived, one-time recovery flow required before '
    'reset_user_vault_state can wipe the current user vault. Requires a valid '
    'OPAQUE reauth proof — a bare session refresh cannot satisfy this.';

-- ============================================================
-- 5. begin_account_delete_challenge — now requires a reauth proof
-- ============================================================

-- Drop the old no-argument version that used iat freshness.
DROP FUNCTION IF EXISTS public.begin_account_delete_challenge();

CREATE OR REPLACE FUNCTION public.begin_account_delete_challenge(
    p_reauth_proof_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    RETURN public.issue_sensitive_action_challenge('account_delete', 180, p_reauth_proof_id);
END;
$$;

REVOKE ALL ON FUNCTION public.begin_account_delete_challenge(UUID) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.begin_account_delete_challenge(UUID) TO authenticated;

COMMENT ON FUNCTION public.begin_account_delete_challenge(UUID) IS
    'Issues a short-lived, one-time challenge required before delete_my_account '
    'can wipe the account. Requires a valid OPAQUE reauth proof — a bare session '
    'refresh cannot satisfy this.';

-- ============================================================
-- 6. Drop the legacy delete_my_account(UUID) overload
--    that only required iat freshness via require_recent_reauthentication.
--    The hardened delete_my_account(UUID, UUID) in migration 20260517000001
--    (which requires a one-time sensitive_action_challenge) is the only
--    remaining overload.
-- ============================================================

DROP FUNCTION IF EXISTS public.delete_my_account(UUID);
