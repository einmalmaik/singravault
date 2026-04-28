-- Device-Key protection metadata.
--
-- This migration intentionally stores only non-sensitive security
-- configuration. It must never contain the Device Key, a hash/fingerprint of
-- the Device Key, transfer secrets, transfer envelopes, or derived key
-- material. The flag lets clients distinguish "this vault requires a local
-- Device Key" from ordinary master-password failures without weakening
-- zero-knowledge encryption.

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS vault_protection_mode TEXT NOT NULL DEFAULT 'master_only',
  ADD COLUMN IF NOT EXISTS device_key_version INTEGER,
  ADD COLUMN IF NOT EXISTS device_key_enabled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS device_key_backup_acknowledged_at TIMESTAMPTZ;

ALTER TABLE public.profiles
  DROP CONSTRAINT IF EXISTS profiles_vault_protection_mode_check,
  ADD CONSTRAINT profiles_vault_protection_mode_check
    CHECK (vault_protection_mode IN ('master_only', 'device_key_required'));

ALTER TABLE public.profiles
  DROP CONSTRAINT IF EXISTS profiles_device_key_version_check,
  ADD CONSTRAINT profiles_device_key_version_check
    CHECK (
      (vault_protection_mode = 'master_only' AND device_key_version IS NULL AND device_key_enabled_at IS NULL)
      OR
      (vault_protection_mode = 'device_key_required' AND device_key_version = 1 AND device_key_enabled_at IS NOT NULL)
    );

COMMENT ON COLUMN public.profiles.vault_protection_mode IS
  'Non-secret vault protection mode. device_key_required means the client must use the local Device Key in key derivation; this is not a Device Key, hash, fingerprint, or recovery material.';

COMMENT ON COLUMN public.profiles.device_key_version IS
  'Non-secret Device Key derivation format version. NULL for master_only; 1 for SINGRA_DEVICE_KEY_V1.';

COMMENT ON COLUMN public.profiles.device_key_enabled_at IS
  'Non-secret timestamp for when Device-Key-required protection was enabled.';

COMMENT ON COLUMN public.profiles.device_key_backup_acknowledged_at IS
  'Non-secret timestamp recording that the user acknowledged Device Key backup/recovery risk.';
