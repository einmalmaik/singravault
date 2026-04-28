DO $finish_opaque_password_reset_permissions$
BEGIN
    EXECUTE 'REVOKE ALL ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) TO service_role';
    EXECUTE 'COMMENT ON FUNCTION public.finish_opaque_password_reset(UUID, UUID, TEXT) IS ''Atomically consumes authorized reset state, writes the new OPAQUE record, clears GoTrue password login, revokes sessions, and cleans reset state.''';
END;
$finish_opaque_password_reset_permissions$;
