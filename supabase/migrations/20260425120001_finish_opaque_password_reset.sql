DO $record_auth_rate_limit_failure_atomic_permissions$
BEGIN
    EXECUTE 'REVOKE ALL ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) TO service_role';
    EXECUTE 'COMMENT ON FUNCTION public.record_auth_rate_limit_failure_atomic(TEXT, TEXT, TEXT, INTEGER, INTEGER, INTEGER) IS ''Records an auth failure under advisory locks and returns the post-insert failure count and lockout in one transaction.''';
END;
$record_auth_rate_limit_failure_atomic_permissions$;
