-- Reserved migration slot for vault reset recovery.
--
-- The destructive reset RPC is intentionally not created here. A prior branch
-- revision exposed a SECURITY DEFINER no-argument reset_user_vault_state()
-- callable by any authenticated session. The hardened implementation is
-- introduced in 20260423193000_harden_vault_reset_recovery.sql, where reset
-- requires a fresh JWT and a short-lived one-time recovery challenge.

DROP FUNCTION IF EXISTS public.reset_user_vault_state();

CREATE OR REPLACE FUNCTION public.reset_user_vault_state()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    RAISE EXCEPTION 'RESET_REQUIRES_HARDENED_MIGRATION';
END;
$$;

REVOKE ALL ON FUNCTION public.reset_user_vault_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reset_user_vault_state() FROM anon;
REVOKE ALL ON FUNCTION public.reset_user_vault_state() FROM authenticated;

COMMENT ON FUNCTION public.reset_user_vault_state() IS
    'Disabled placeholder. The destructive vault reset is available only as reset_user_vault_state(UUID) after the hardened recovery migration.';
