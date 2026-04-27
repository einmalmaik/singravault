-- Bind WebAuthn challenges to the RP/origin and, for authentication, the
-- expected credential. Verification must consume the exact challenge ID rather
-- than the latest challenge for a user/type pair.

ALTER TABLE public.webauthn_challenges
    ADD COLUMN IF NOT EXISTS rp_id TEXT,
    ADD COLUMN IF NOT EXISTS origin TEXT,
    ADD COLUMN IF NOT EXISTS credential_id TEXT;

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_id_id
    ON public.webauthn_challenges(user_id, id);

COMMENT ON COLUMN public.webauthn_challenges.rp_id IS
    'Relying-party ID used when the challenge was issued.';
COMMENT ON COLUMN public.webauthn_challenges.origin IS
    'HTTP origin used when the challenge was issued.';
COMMENT ON COLUMN public.webauthn_challenges.credential_id IS
    'Expected credential ID for authentication challenges, when scoped to one credential.';
