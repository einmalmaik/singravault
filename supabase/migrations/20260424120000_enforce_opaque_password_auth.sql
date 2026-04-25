-- Enforce OPAQUE as the only app-owned password authentication path.

ALTER TABLE public.user_opaque_records
    ADD COLUMN IF NOT EXISTS opaque_identifier TEXT;

UPDATE public.user_opaque_records AS records
SET opaque_identifier = LOWER(TRIM(users.email::TEXT))
FROM auth.users AS users
WHERE records.user_id = users.id
  AND records.opaque_identifier IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_opaque_records_identifier
    ON public.user_opaque_records(opaque_identifier)
    WHERE opaque_identifier IS NOT NULL;

COMMENT ON COLUMN public.user_opaque_records.opaque_identifier IS
    'Normalized OPAQUE identifier used for registration and login. OAuth/social-only accounts do not need a row here.';

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

INSERT INTO public.opaque_reenrollment_required (user_id, email)
SELECT users.id, LOWER(TRIM(users.email::TEXT))
FROM auth.users AS users
LEFT JOIN public.user_opaque_records AS records ON records.user_id = users.id
WHERE users.encrypted_password IS NOT NULL
  AND users.email IS NOT NULL
  AND records.user_id IS NULL
ON CONFLICT (user_id) DO NOTHING;

ALTER TABLE public.opaque_login_states
    ADD COLUMN IF NOT EXISTS opaque_identifier TEXT;

COMMENT ON COLUMN public.opaque_login_states.opaque_identifier IS
    'Normalized OPAQUE identifier bound to this one-time login state.';

CREATE TABLE IF NOT EXISTS public.opaque_registration_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('signup', 'signup-decoy')),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_opaque_registration_challenges_email
    ON public.opaque_registration_challenges(email, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE public.opaque_registration_challenges ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.opaque_registration_challenges FROM PUBLIC;
REVOKE ALL ON TABLE public.opaque_registration_challenges FROM anon;
REVOKE ALL ON TABLE public.opaque_registration_challenges FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.opaque_registration_challenges TO service_role;

COMMENT ON TABLE public.opaque_registration_challenges IS
    'Short-lived server-side state for two-step OPAQUE signup registration. Decoy rows prevent signup enumeration from becoming a record overwrite path.';

CREATE TABLE IF NOT EXISTS public.opaque_password_reset_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_opaque_password_reset_states_user
    ON public.opaque_password_reset_states(user_id, expires_at)
    WHERE consumed_at IS NULL;

ALTER TABLE public.opaque_password_reset_states ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.opaque_password_reset_states FROM PUBLIC;
REVOKE ALL ON TABLE public.opaque_password_reset_states FROM anon;
REVOKE ALL ON TABLE public.opaque_password_reset_states FROM authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.opaque_password_reset_states TO service_role;

COMMENT ON TABLE public.opaque_password_reset_states IS
    'Short-lived state for OPAQUE password-reset registration; stores no password or password-equivalent material.';

CREATE OR REPLACE FUNCTION public.get_user_id_by_email(p_email TEXT)
RETURNS TABLE (id UUID, email TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  normalized_email TEXT := LOWER(TRIM(p_email));
BEGIN
  RETURN QUERY
  SELECT u.id, u.email::TEXT
  FROM auth.users u
  WHERE LOWER(TRIM(u.email::TEXT)) = normalized_email
  LIMIT 1;
END;
$$;

REVOKE ALL ON FUNCTION public.get_user_id_by_email(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_user_id_by_email(TEXT) TO service_role;

COMMENT ON COLUMN public.profiles.auth_protocol IS
    'Metadata for app-owned password authentication. Password login is only allowed through OPAQUE; OAuth/social accounts are separate and do not require an OPAQUE identifier.';

UPDATE public.profiles AS profiles
SET auth_protocol = 'opaque'
FROM public.user_opaque_records AS records
WHERE records.user_id = profiles.user_id;

CREATE OR REPLACE FUNCTION public.disable_gotrue_password_login(p_user_id UUID)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  UPDATE auth.users
  SET encrypted_password = NULL,
      updated_at = NOW()
  WHERE id = p_user_id;
END;
$$;

REVOKE ALL ON FUNCTION public.disable_gotrue_password_login(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.disable_gotrue_password_login(UUID) TO service_role;

COMMENT ON FUNCTION public.disable_gotrue_password_login(UUID) IS
    'Removes the GoTrue password verifier so direct Supabase password grants cannot bypass the OPAQUE app-password login path.';

-- Cut over all existing accounts: app-owned password login is no longer allowed
-- through Supabase GoTrue's password grant. OAuth/social identities keep working
-- because they do not depend on auth.users.encrypted_password.
UPDATE auth.users
SET encrypted_password = NULL,
    updated_at = NOW()
WHERE encrypted_password IS NOT NULL;
