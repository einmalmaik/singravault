-- Ensure the OAuth reauth freshness helper remains callable only by Edge
-- Functions using the service-role key. The previous migration already
-- revoked PUBLIC, but Supabase role defaults also need explicit revokes for
-- anon/authenticated on the deployed project.

REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM anon;
REVOKE ALL ON FUNCTION public.check_recent_social_login(UUID, INTEGER) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.check_recent_social_login(UUID, INTEGER) TO service_role;
