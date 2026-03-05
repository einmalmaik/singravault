-- ============================================
-- Require recent reauthentication for account deletion
-- Enforces max JWT age of 5 minutes based on iat claim.
-- ============================================

DROP FUNCTION IF EXISTS public.delete_my_account();

CREATE OR REPLACE FUNCTION public.delete_my_account()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _jwt jsonb := auth.jwt();
    _iat_text TEXT;
    _iat BIGINT;
    _now_epoch BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
    _deleted_auth_rows INTEGER := 0;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    _iat_text := _jwt ->> 'iat';
    IF _iat_text IS NULL OR _iat_text !~ '^\d+$' THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    _iat := _iat_text::BIGINT;
    IF (_now_epoch - _iat) > 300 THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    -- Explicit cleanup first (defensive), then auth deletion.
    DELETE FROM public.vault_item_tags
    WHERE vault_item_id IN (
        SELECT id FROM public.vault_items WHERE user_id = _uid
    );

    DELETE FROM public.vault_items WHERE user_id = _uid;
    DELETE FROM public.categories WHERE user_id = _uid;
    DELETE FROM public.tags WHERE user_id = _uid;
    DELETE FROM public.vaults WHERE user_id = _uid;
    DELETE FROM public.user_roles WHERE user_id = _uid;
    DELETE FROM public.profiles WHERE user_id = _uid;

    DELETE FROM auth.users WHERE id = _uid;
    GET DIAGNOSTICS _deleted_auth_rows = ROW_COUNT;

    IF _deleted_auth_rows = 0 THEN
        RAISE EXCEPTION 'Auth user deletion failed';
    END IF;

    RETURN jsonb_build_object('deleted', true, 'user_id', _uid);
END;
$$;

REVOKE ALL ON FUNCTION public.delete_my_account() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.delete_my_account() TO authenticated;
