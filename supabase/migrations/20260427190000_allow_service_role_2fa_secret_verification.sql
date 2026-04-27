-- Allow server-side 2FA verification from Edge Functions.
--
-- auth-2fa validates the caller's JWT before it verifies a TOTP code, then uses
-- the service-role client for the secret lookup. In that context auth.uid() is
-- not the end user's id, so the previous user-only guard rejected legitimate
-- server-side verification with "Forbidden".
CREATE OR REPLACE FUNCTION public.get_user_2fa_secret(
    p_user_id UUID,
    p_require_enabled BOOLEAN DEFAULT true
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _role TEXT := auth.role();
    _secret_enc TEXT;
    _legacy_secret TEXT;
    _is_enabled BOOLEAN;
BEGIN
    IF (_uid IS NULL OR _uid <> p_user_id) AND _role <> 'service_role' THEN
        RAISE EXCEPTION 'Forbidden';
    END IF;

    SELECT totp_secret_enc, totp_secret, COALESCE(is_enabled, false)
    INTO _secret_enc, _legacy_secret, _is_enabled
    FROM public.user_2fa
    WHERE user_id = p_user_id
    LIMIT 1;

    IF _secret_enc IS NULL AND _legacy_secret IS NULL THEN
        RETURN NULL;
    END IF;

    IF p_require_enabled AND NOT _is_enabled THEN
        RETURN NULL;
    END IF;

    IF _secret_enc IS NOT NULL THEN
        RETURN public.user_2fa_decrypt_secret(_secret_enc);
    END IF;

    -- One-time fallback migration from plaintext.
    UPDATE public.user_2fa
    SET totp_secret_enc = public.user_2fa_encrypt_secret(_legacy_secret),
        totp_secret = NULL
    WHERE user_id = p_user_id;

    RETURN _legacy_secret;
END;
$$;

REVOKE ALL ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO service_role;
