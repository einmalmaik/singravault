-- Restrict sensitive helper RPCs that are called by service-role Edge Functions
-- or by SECURITY DEFINER wrappers. They must not be directly executable by
-- anonymous or normal authenticated clients.

REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role;

REVOKE ALL ON FUNCTION public.revoke_user_auth_sessions(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.revoke_user_auth_sessions(UUID) FROM anon;
REVOKE ALL ON FUNCTION public.revoke_user_auth_sessions(UUID) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.revoke_user_auth_sessions(UUID) TO service_role;

REVOKE ALL ON FUNCTION public.rotate_totp_encryption_key(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rotate_totp_encryption_key(TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.rotate_totp_encryption_key(TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.rotate_totp_encryption_key(TEXT) TO service_role;

REVOKE ALL ON FUNCTION public.user_2fa_encrypt_secret(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.user_2fa_encrypt_secret(TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.user_2fa_encrypt_secret(TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.user_2fa_encrypt_secret(TEXT) TO service_role;

REVOKE ALL ON FUNCTION public.user_2fa_decrypt_secret(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.user_2fa_decrypt_secret(TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.user_2fa_decrypt_secret(TEXT) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.user_2fa_decrypt_secret(TEXT) TO service_role;
