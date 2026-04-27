-- Security Standard v1 rollout metadata and hybrid enforcement constraints

ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS security_standard_version INTEGER NULL;

ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS legacy_crypto_disabled_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN public.profiles.security_standard_version IS
'Security standard version applied to this account. v1 enforces hybrid ML-KEM-768 + RSA-4096 key exchange for sharing/emergency keys.';

COMMENT ON COLUMN public.profiles.legacy_crypto_disabled_at IS
'UTC timestamp when legacy RSA-only crypto paths were disabled for this account.';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'profiles_security_standard_version_check'
          AND conrelid = 'public.profiles'::regclass
    ) THEN
        ALTER TABLE public.profiles
        ADD CONSTRAINT profiles_security_standard_version_check
        CHECK (security_standard_version IS NULL OR security_standard_version IN (0, 1));
    END IF;
END;
$$;

-- Backfill existing PQ-enabled profiles to Security Standard v1 metadata
UPDATE public.profiles
SET
    security_standard_version = 1,
    pq_enforced_at = COALESCE(pq_enforced_at, NOW()),
    legacy_crypto_disabled_at = COALESCE(legacy_crypto_disabled_at, COALESCE(pq_enforced_at, NOW()))
WHERE pq_public_key IS NOT NULL
  AND pq_key_version IS NOT NULL
  AND (
      security_standard_version IS DISTINCT FROM 1
      OR pq_enforced_at IS NULL
      OR legacy_crypto_disabled_at IS NULL
  );

CREATE INDEX IF NOT EXISTS idx_profiles_security_standard_version
ON public.profiles (security_standard_version)
WHERE security_standard_version IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_profiles_legacy_crypto_disabled_at
ON public.profiles (legacy_crypto_disabled_at)
WHERE legacy_crypto_disabled_at IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'collection_keys_require_pq_wrapped_key_check'
          AND conrelid = 'public.collection_keys'::regclass
    ) THEN
        ALTER TABLE public.collection_keys
        ADD CONSTRAINT collection_keys_require_pq_wrapped_key_check
        CHECK (pq_wrapped_key IS NOT NULL)
        NOT VALID;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'emergency_access_requires_trustee_pq_key_check'
          AND conrelid = 'public.emergency_access'::regclass
    ) THEN
        ALTER TABLE public.emergency_access
        ADD CONSTRAINT emergency_access_requires_trustee_pq_key_check
        CHECK (
            status NOT IN ('accepted', 'pending', 'granted', 'rejected', 'expired')
            OR trustee_pq_public_key IS NOT NULL
        )
        NOT VALID;
    END IF;
END;
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'emergency_access_requires_pq_master_key_check'
          AND conrelid = 'public.emergency_access'::regclass
    ) THEN
        ALTER TABLE public.emergency_access
        ADD CONSTRAINT emergency_access_requires_pq_master_key_check
        CHECK (
            status NOT IN ('pending', 'granted', 'rejected', 'expired')
            OR pq_encrypted_master_key IS NOT NULL
        )
        NOT VALID;
    END IF;
END;
$$;
