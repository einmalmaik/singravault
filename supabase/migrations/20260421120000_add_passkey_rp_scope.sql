-- Migration: Scope passkey credentials to their relying party ID (RP ID)
-- WebAuthn credentials are only valid for the RP they were created for.
-- We keep legacy rows nullable and treat them as hosted-web credentials in the
-- edge function so existing website passkeys remain usable.

ALTER TABLE public.passkey_credentials
ADD COLUMN IF NOT EXISTS rp_id TEXT;

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_rp
ON public.passkey_credentials(user_id, rp_id);

COMMENT ON COLUMN public.passkey_credentials.rp_id IS 'WebAuthn relying-party identifier (for example singravault.mauntingstudios.de or tauri.localhost)';
