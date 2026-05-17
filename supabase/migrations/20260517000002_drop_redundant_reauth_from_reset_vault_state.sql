-- Remove the redundant require_recent_reauthentication(300) call from
-- reset_user_vault_state. The function already requires a one-time
-- sensitive_action_challenge that is only issuable when the JWT iat is fresh
-- (enforced inside issue_sensitive_action_challenge via the same
-- require_recent_reauthentication check). Calling require_recent_reauthentication
-- a second time inside the consuming function is redundant and can cause
-- spurious REAUTH_REQUIRED failures when the challenge was legitimately issued
-- near the end of the freshness window and the operation is performed shortly
-- after the window expires.

CREATE OR REPLACE FUNCTION public.reset_user_vault_state(
    p_recovery_challenge_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _deleted_storage_objects INTEGER := 0;
    _deleted_attachments INTEGER := 0;
    _deleted_items INTEGER := 0;
    _deleted_categories INTEGER := 0;
    _deleted_tags INTEGER := 0;
    _deleted_vaults INTEGER := 0;
BEGIN
    -- Require an explicit, short-lived recovery flow. The challenge was only
    -- issuable when the JWT iat was fresh, so consuming it here is sufficient
    -- proof of recent reauthentication without a second iat check.
    PERFORM public.consume_sensitive_action_challenge(
        'vault_reset_recovery',
        p_recovery_challenge_id
    );

    DELETE FROM storage.objects
    WHERE bucket_id = 'vault-attachments'
      AND (
          owner = _uid
          OR name LIKE (_uid::TEXT || '/%')
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

REVOKE ALL ON FUNCTION public.reset_user_vault_state(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reset_user_vault_state(UUID) TO authenticated;

COMMENT ON FUNCTION public.reset_user_vault_state(UUID) IS
    'Atomically clears the authenticated user vault state only after consuming a short-lived recovery challenge that was issued during a fresh reauthentication window.';
