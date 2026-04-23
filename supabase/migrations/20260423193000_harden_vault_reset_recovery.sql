-- Harden reset_user_vault_state with fresh reauthentication and an explicit,
-- short-lived recovery challenge so stale sessions cannot wipe the vault.

CREATE TABLE IF NOT EXISTS public.sensitive_action_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, action)
);

CREATE INDEX IF NOT EXISTS idx_sensitive_action_challenges_user_expires_at
    ON public.sensitive_action_challenges (user_id, expires_at);

ALTER TABLE public.sensitive_action_challenges ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.sensitive_action_challenges FROM PUBLIC;
REVOKE ALL ON TABLE public.sensitive_action_challenges FROM anon;
REVOKE ALL ON TABLE public.sensitive_action_challenges FROM authenticated;

COMMENT ON TABLE public.sensitive_action_challenges IS
    'Short-lived, one-time server challenges for destructive user actions.';

CREATE OR REPLACE FUNCTION public.require_recent_reauthentication(
    p_max_age_seconds INTEGER DEFAULT 300
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _jwt JSONB := auth.jwt();
    _iat_text TEXT;
    _iat BIGINT;
    _now_epoch BIGINT := EXTRACT(EPOCH FROM NOW())::BIGINT;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_max_age_seconds IS NULL OR p_max_age_seconds <= 0 THEN
        RAISE EXCEPTION 'Invalid reauthentication window';
    END IF;

    _iat_text := _jwt ->> 'iat';
    IF _iat_text IS NULL OR _iat_text !~ '^\d+$' THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    _iat := _iat_text::BIGINT;
    IF _iat > (_now_epoch + 30) OR (_now_epoch - _iat) > p_max_age_seconds THEN
        RAISE EXCEPTION 'REAUTH_REQUIRED';
    END IF;

    RETURN _iat;
END;
$$;

REVOKE ALL ON FUNCTION public.require_recent_reauthentication(INTEGER) FROM PUBLIC;

COMMENT ON FUNCTION public.require_recent_reauthentication(INTEGER) IS
    'Raises REAUTH_REQUIRED unless the current JWT iat is within the allowed age window.';

CREATE OR REPLACE FUNCTION public.issue_sensitive_action_challenge(
    p_action TEXT,
    p_ttl_seconds INTEGER DEFAULT 300
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _challenge_id UUID := gen_random_uuid();
    _expires_at TIMESTAMPTZ;
BEGIN
    PERFORM public.require_recent_reauthentication(300);

    IF p_action IS NULL OR btrim(p_action) = '' THEN
        RAISE EXCEPTION 'Invalid sensitive action';
    END IF;

    IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 OR p_ttl_seconds > 900 THEN
        RAISE EXCEPTION 'Invalid challenge ttl';
    END IF;

    DELETE FROM public.sensitive_action_challenges
    WHERE user_id = _uid
      AND (action = p_action OR expires_at <= NOW());

    _expires_at := NOW() + make_interval(secs => p_ttl_seconds);

    INSERT INTO public.sensitive_action_challenges (
        id,
        user_id,
        action,
        expires_at
    )
    VALUES (
        _challenge_id,
        _uid,
        p_action,
        _expires_at
    );

    RETURN jsonb_build_object(
        'challenge_id', _challenge_id,
        'action', p_action,
        'expires_at', _expires_at
    );
END;
$$;

REVOKE ALL ON FUNCTION public.issue_sensitive_action_challenge(TEXT, INTEGER) FROM PUBLIC;

COMMENT ON FUNCTION public.issue_sensitive_action_challenge(TEXT, INTEGER) IS
    'Creates a short-lived, one-time challenge for a sensitive user action after fresh reauthentication.';

CREATE OR REPLACE FUNCTION public.consume_sensitive_action_challenge(
    p_action TEXT,
    p_challenge_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
    _consumed_id UUID;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_action IS NULL OR btrim(p_action) = '' OR p_challenge_id IS NULL THEN
        RAISE EXCEPTION 'RECOVERY_CHALLENGE_REQUIRED';
    END IF;

    DELETE FROM public.sensitive_action_challenges
    WHERE user_id = _uid
      AND expires_at <= NOW();

    DELETE FROM public.sensitive_action_challenges
    WHERE user_id = _uid
      AND action = p_action
      AND id = p_challenge_id
      AND expires_at > NOW()
    RETURNING id INTO _consumed_id;

    IF _consumed_id IS NULL THEN
        RAISE EXCEPTION 'RECOVERY_CHALLENGE_REQUIRED';
    END IF;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_sensitive_action_challenge(TEXT, UUID) FROM PUBLIC;

COMMENT ON FUNCTION public.consume_sensitive_action_challenge(TEXT, UUID) IS
    'Consumes a short-lived, one-time challenge and raises RECOVERY_CHALLENGE_REQUIRED when it is missing or expired.';

DROP FUNCTION IF EXISTS public.begin_vault_reset_recovery();

CREATE OR REPLACE FUNCTION public.begin_vault_reset_recovery()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    RETURN public.issue_sensitive_action_challenge('vault_reset_recovery', 300);
END;
$$;

REVOKE ALL ON FUNCTION public.begin_vault_reset_recovery() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.begin_vault_reset_recovery() TO authenticated;

COMMENT ON FUNCTION public.begin_vault_reset_recovery() IS
    'Starts the short-lived, one-time recovery flow required before reset_user_vault_state can wipe the current user vault.';

DROP FUNCTION IF EXISTS public.reset_user_vault_state();

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
    PERFORM public.require_recent_reauthentication(300);

    -- Require an explicit, short-lived recovery flow in addition to fresh reauth.
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
    'Atomically clears the authenticated user vault state only after fresh reauthentication and a short-lived recovery challenge.';
