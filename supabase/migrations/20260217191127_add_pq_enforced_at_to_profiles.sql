-- Add enforcement timestamp for post-quantum rollout state
ALTER TABLE public.profiles
ADD COLUMN IF NOT EXISTS pq_enforced_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN public.profiles.pq_enforced_at IS
'UTC timestamp when post-quantum hybrid key wrapping for sharing/emergency keys was enforced for this account.';

CREATE INDEX IF NOT EXISTS idx_profiles_pq_enforced_at
ON public.profiles (pq_enforced_at)
WHERE pq_enforced_at IS NOT NULL;
