-- Reset only the authenticated user's vault state in one database transaction.
-- PostgreSQL executes the function body atomically: any raised error rolls back
-- all deletes and updates below, so the client never observes a half-reset vault.

DROP FUNCTION IF EXISTS public.reset_user_vault_state();

CREATE OR REPLACE FUNCTION public.reset_user_vault_state()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid uuid := auth.uid();
    _deleted_storage_objects integer := 0;
    _deleted_attachments integer := 0;
    _deleted_items integer := 0;
    _deleted_categories integer := 0;
    _deleted_tags integer := 0;
    _deleted_vaults integer := 0;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    DELETE FROM storage.objects
    WHERE bucket_id = 'vault-attachments'
      AND (
          owner = _uid
          OR name LIKE (_uid::text || '/%')
      );
    GET DIAGNOSTICS _deleted_storage_objects = ROW_COUNT;

    DELETE FROM public.file_attachments
    WHERE user_id = _uid;
    GET DIAGNOSTICS _deleted_attachments = ROW_COUNT;

    DELETE FROM public.vault_item_tags
    WHERE vault_item_id IN (
        SELECT id FROM public.vault_items WHERE user_id = _uid
    )
    OR tag_id IN (
        SELECT id FROM public.tags WHERE user_id = _uid
    );

    DELETE FROM public.vault_items
    WHERE user_id = _uid;
    GET DIAGNOSTICS _deleted_items = ROW_COUNT;

    DELETE FROM public.categories
    WHERE user_id = _uid;
    GET DIAGNOSTICS _deleted_categories = ROW_COUNT;

    DELETE FROM public.tags
    WHERE user_id = _uid;
    GET DIAGNOSTICS _deleted_tags = ROW_COUNT;

    DELETE FROM public.user_keys
    WHERE user_id = _uid;

    DELETE FROM public.vaults
    WHERE user_id = _uid;
    GET DIAGNOSTICS _deleted_vaults = ROW_COUNT;

    UPDATE public.passkey_credentials
    SET
        wrapped_master_key = NULL,
        prf_enabled = FALSE
    WHERE user_id = _uid;

    UPDATE public.profiles
    SET
        encryption_salt = NULL,
        master_password_verifier = NULL,
        kdf_version = 1,
        duress_kdf_version = NULL,
        duress_password_verifier = NULL,
        duress_salt = NULL,
        pq_encrypted_private_key = NULL,
        pq_enforced_at = NULL,
        pq_key_version = NULL,
        pq_public_key = NULL,
        encrypted_user_key = NULL,
        updated_at = NOW()
    WHERE user_id = _uid;

    RETURN jsonb_build_object(
        'reset', true,
        'user_id', _uid,
        'deleted_storage_objects', _deleted_storage_objects,
        'deleted_attachments', _deleted_attachments,
        'deleted_items', _deleted_items,
        'deleted_categories', _deleted_categories,
        'deleted_tags', _deleted_tags,
        'deleted_vaults', _deleted_vaults
    );
END;
$$;

REVOKE ALL ON FUNCTION public.reset_user_vault_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reset_user_vault_state() TO authenticated;

COMMENT ON FUNCTION public.reset_user_vault_state() IS
    'Atomically clears the authenticated user vault state while preserving the auth account and passkey credentials.';
