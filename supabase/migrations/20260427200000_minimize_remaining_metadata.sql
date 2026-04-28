-- Minimize remaining plaintext metadata after the E2EE hardening work.
--
-- This migration intentionally separates two classes of data:
-- 1. Confirmed legacy/unneeded plaintext columns that can be removed now.
-- 2. Legacy vault metadata columns still referenced by the current app/types,
--    which are neutralized now and can be dropped in a later code/schema cleanup.

-- ---------------------------------------------------------------------------
-- user_2fa: remove the legacy plaintext TOTP secret column.
-- ---------------------------------------------------------------------------

-- Preserve any unexpected legacy plaintext value by encrypting it first. Some
-- environments already dropped this legacy column, so the reference must be
-- guarded before the statement is parsed.
DO $migrate_legacy_user_2fa_totp_secret$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'user_2fa'
          AND column_name = 'totp_secret'
    ) THEN
        EXECUTE $sql$
            UPDATE public.user_2fa
            SET totp_secret_enc = public.user_2fa_encrypt_secret(totp_secret),
                totp_secret = NULL
            WHERE totp_secret IS NOT NULL
              AND totp_secret_enc IS NULL
        $sql$;
    END IF;
END;
$migrate_legacy_user_2fa_totp_secret$;

-- initialize_user_2fa_secret no longer writes the removed plaintext column.
CREATE OR REPLACE FUNCTION public.initialize_user_2fa_secret(
    p_user_id UUID,
    p_secret TEXT
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
DECLARE
    _uid UUID := auth.uid();
BEGIN
    IF _uid IS NULL OR _uid <> p_user_id THEN
        RAISE EXCEPTION 'Forbidden';
    END IF;

    DELETE FROM public.user_2fa
    WHERE user_id = p_user_id
      AND COALESCE(is_enabled, false) = false;

    INSERT INTO public.user_2fa (
        user_id,
        totp_secret_enc,
        is_enabled
    )
    VALUES (
        p_user_id,
        public.user_2fa_encrypt_secret(p_secret),
        false
    );
END;
$$;

-- get_user_2fa_secret now only reads the encrypted secret. The legacy plaintext
-- fallback is removed together with the column.
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
    _is_enabled BOOLEAN;
BEGIN
    IF (_uid IS NULL OR _uid <> p_user_id) AND _role <> 'service_role' THEN
        RAISE EXCEPTION 'Forbidden';
    END IF;

    SELECT totp_secret_enc, COALESCE(is_enabled, false)
    INTO _secret_enc, _is_enabled
    FROM public.user_2fa
    WHERE user_id = p_user_id
    LIMIT 1;

    IF _secret_enc IS NULL THEN
        RETURN NULL;
    END IF;

    IF p_require_enabled AND NOT _is_enabled THEN
        RETURN NULL;
    END IF;

    RETURN public.user_2fa_decrypt_secret(_secret_enc);
END;
$$;

-- rotate_totp_encryption_key no longer contains a plaintext fallback path.
CREATE OR REPLACE FUNCTION public.rotate_totp_encryption_key(
    p_new_key TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, private
AS $$
DECLARE
    _old_key TEXT;
    _rotated_count INTEGER := 0;
BEGIN
    IF p_new_key IS NULL OR length(trim(p_new_key)) = 0 THEN
        RAISE EXCEPTION 'New key must not be empty';
    END IF;

    IF p_new_key !~ '^[0-9a-fA-F]{64}$' THEN
        RAISE EXCEPTION 'Invalid key format: expected 64 hex chars';
    END IF;

    SELECT value INTO _old_key
    FROM private.app_secrets
    WHERE name = 'totp_encryption_key'
    LIMIT 1;

    IF _old_key IS NULL THEN
        RAISE EXCEPTION 'Missing secret private.app_secrets(totp_encryption_key)';
    END IF;

    IF lower(_old_key) = lower(p_new_key) THEN
        RAISE EXCEPTION 'New key equals current key';
    END IF;

    UPDATE public.user_2fa
    SET totp_secret_enc = encode(
        pgp_sym_encrypt(
            pgp_sym_decrypt(decode(totp_secret_enc, 'base64'), _old_key),
            p_new_key,
            'cipher-algo=aes256, compress-algo=1'::text
        ),
        'base64'
    )
    WHERE totp_secret_enc IS NOT NULL;

    GET DIAGNOSTICS _rotated_count = ROW_COUNT;

    UPDATE private.app_secrets
    SET value = lower(p_new_key)
    WHERE name = 'totp_encryption_key';

    RETURN _rotated_count;
END;
$$;

ALTER TABLE public.user_2fa
DROP COLUMN IF EXISTS totp_secret;

REVOKE ALL ON FUNCTION public.initialize_user_2fa_secret(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rotate_totp_encryption_key(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.initialize_user_2fa_secret(UUID, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO service_role;

-- ---------------------------------------------------------------------------
-- vault_items: neutralize semantic legacy metadata.
-- ---------------------------------------------------------------------------

-- Only neutralize rows that already use the encrypted-item placeholder. SQL
-- cannot decrypt encrypted_data, so rows with legacy plaintext title metadata
-- must first be migrated by the client re-encryption path before these fallback
-- columns can be wiped without risking data loss.
UPDATE public.vault_items
SET title = 'Encrypted Item',
    website_url = NULL,
    icon_url = NULL,
    item_type = 'password',
    is_favorite = false,
    category_id = NULL,
    sort_order = NULL,
    last_used_at = NULL
WHERE title = 'Encrypted Item';

ALTER TABLE public.vault_items
    ALTER COLUMN title SET DEFAULT 'Encrypted Item',
    ALTER COLUMN website_url SET DEFAULT NULL,
    ALTER COLUMN icon_url SET DEFAULT NULL,
    ALTER COLUMN item_type SET DEFAULT 'password',
    ALTER COLUMN is_favorite SET DEFAULT false,
    ALTER COLUMN category_id SET DEFAULT NULL,
    ALTER COLUMN sort_order SET DEFAULT NULL,
    ALTER COLUMN last_used_at SET DEFAULT NULL;

DROP INDEX IF EXISTS public.idx_vault_items_category_id;
DROP INDEX IF EXISTS public.idx_vault_items_is_favorite;

COMMENT ON COLUMN public.vault_items.title IS
    'Opaque placeholder only. Real item title is inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.website_url IS
    'Deprecated plaintext metadata column. Real website URL is inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.icon_url IS
    'Deprecated plaintext metadata column. Real icon metadata, if any, must be inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.item_type IS
    'Opaque compatibility placeholder only. Real item type is inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.is_favorite IS
    'Opaque compatibility placeholder only. Real favorite state is inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.category_id IS
    'Deprecated plaintext metadata relation. Real category assignment is inside encrypted_data.';
COMMENT ON COLUMN public.vault_items.sort_order IS
    'Deprecated plaintext ordering metadata. Ordering must be derived client-side or encrypted.';
COMMENT ON COLUMN public.vault_items.last_used_at IS
    'Deprecated plaintext usage metadata. Avoid writing user behavior timestamps here.';
