-- Track interactive OAuth logins server-side so that account deletion can
-- verify freshness without relying on JWT amr claims.
--
-- Problem with the JWT amr approach:
--   The edgeFunctionService automatically refreshes the access token before
--   calling the auth-session edge function. After a silent BFF refresh the
--   token carries amr: [{method:"refresh"}], which isJwtSessionFresh()
--   correctly rejects — but this means the account deletion ALWAYS fails for
--   social-login users whose token is close to expiry, even when they just
--   logged in interactively.
--
-- Fix:
--   1. social_login_events records every interactive OAuth authentication
--      (written only by the service-role key inside the auth-session edge
--      function's handleOAuthSync, never by the client).
--   2. handleOAuthReauth checks social_login_events instead of JWT amr:
--      if the user has an event within the last 15 minutes they get a
--      reauth proof; otherwise they get REAUTH_REQUIRED and need to sign
--      in again.
--   3. The 15-minute window is intentionally generous (vs 5-minute JWT
--      freshness) because the user may have opened the delete dialog a few
--      minutes after logging in. It is still far safer than amr-based
--      checking which the client can bypass by avoiding token refresh.
--
-- Security properties:
--   - Only the service-role key can insert rows (RLS + REVOKE).
--   - authenticated users cannot read or modify their own rows directly.
--   - Rows are deleted on CASCADE when auth.users is deleted.
--   - An index on (user_id, authenticated_at DESC) makes the recency
--     lookup a single-row index scan.

-- ============================================================
-- 1. Create table
-- ============================================================

CREATE TABLE IF NOT EXISTS public.social_login_events (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    provider         TEXT        NOT NULL CHECK (provider <> ''),
    authenticated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE public.social_login_events IS
    'Server-side record of interactive OAuth/social logins. Written exclusively '
    'by the auth-session edge function using the service-role key after a '
    'successful oauth-sync. Used by handleOAuthReauth to verify that the user '
    'actually authenticated interactively within a recent time window, without '
    'relying on JWT amr claims that are invalidated by client-side token refresh.';

-- ============================================================
-- 2. Harden access - authenticated users get no direct access
-- ============================================================

ALTER TABLE public.social_login_events ENABLE ROW LEVEL SECURITY;

-- Revoke client access. The only writer is the edge function running under the
-- service-role key. The only reader is the SECURITY DEFINER helper below.
REVOKE ALL ON TABLE public.social_login_events FROM PUBLIC;
REVOKE ALL ON TABLE public.social_login_events FROM anon;
REVOKE ALL ON TABLE public.social_login_events FROM authenticated;
GRANT INSERT ON TABLE public.social_login_events TO service_role;

-- Reauth proof issuance is shared by auth-opaque and auth-session. Make the
-- service-role dependency explicit so account deletion does not fail closed on
-- projects where new public tables are not auto-granted to Data API roles.
GRANT INSERT, SELECT ON TABLE public.reauth_proofs TO service_role;

-- ============================================================
-- 3. Performance index
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_social_login_events_user_recent
    ON public.social_login_events (user_id, authenticated_at DESC);

-- ============================================================
-- 4. SECURITY DEFINER helper: check_recent_social_login
--    Called by the edge function after obtaining the user id from the
--    service-role auth.getUser() call (passed as a parameter rather than
--    relying on auth.uid() because the function is invoked without a
--    user-scoped JWT in the service-role context).
-- ============================================================

CREATE OR REPLACE FUNCTION public.check_recent_social_login(
    p_user_id      UUID,
    p_max_age_secs INTEGER DEFAULT 900   -- 15 minutes default
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _event_at TIMESTAMPTZ;
BEGIN
    IF p_user_id IS NULL THEN
        RETURN FALSE;
    END IF;

    SELECT authenticated_at
      INTO _event_at
      FROM public.social_login_events
     WHERE user_id = p_user_id
       AND authenticated_at >= NOW() - make_interval(secs => p_max_age_secs)
     ORDER BY authenticated_at DESC
     LIMIT 1;

    RETURN FOUND;
END;
$$;

-- Grant to service_role only (the edge function uses the service-role key).
REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.check_recent_social_login(UUID, INTEGER) TO service_role;

COMMENT ON FUNCTION public.check_recent_social_login(UUID, INTEGER) IS
    'Returns TRUE when the given user has an interactive social-login event '
    'recorded within the last p_max_age_secs seconds. Callable only by the '
    'service role. Used by handleOAuthReauth to gate reauth-proof issuance '
    'without relying on JWT amr claims.';
