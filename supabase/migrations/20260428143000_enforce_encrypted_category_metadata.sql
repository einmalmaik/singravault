-- Enforce client-side encrypted category metadata for future writes.
-- Existing legacy plaintext rows are migrated by the client after unlock, because
-- SQL cannot encrypt them without the user's vault key.

CREATE OR REPLACE FUNCTION public.assert_encrypted_category_metadata(
    p_name TEXT,
    p_icon TEXT,
    p_color TEXT
)
RETURNS VOID
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    -- Category name/icon/color reveal vault structure and must stay
    -- client-side encrypted. SQL can only enforce the versioned envelope
    -- prefix; it cannot validate ciphertext without the user's vault key.
    IF COALESCE(p_name, '') NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category name must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;

    IF p_icon IS NOT NULL AND p_icon NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category icon must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;

    IF p_color IS NOT NULL AND p_color NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category color must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.enforce_encrypted_category_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    PERFORM public.assert_encrypted_category_metadata(NEW.name, NEW.icon, NEW.color);

    NEW.parent_id := NULL;
    NEW.sort_order := NULL;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_encrypted_category_metadata_trigger ON public.categories;
CREATE TRIGGER enforce_encrypted_category_metadata_trigger
    BEFORE INSERT OR UPDATE ON public.categories
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_encrypted_category_metadata();

REVOKE ALL ON FUNCTION public.assert_encrypted_category_metadata(TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_encrypted_category_metadata(TEXT, TEXT, TEXT) FROM anon;
REVOKE ALL ON FUNCTION public.assert_encrypted_category_metadata(TEXT, TEXT, TEXT) FROM authenticated;

REVOKE ALL ON FUNCTION public.enforce_encrypted_category_metadata() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.enforce_encrypted_category_metadata() FROM anon;
REVOKE ALL ON FUNCTION public.enforce_encrypted_category_metadata() FROM authenticated;

COMMENT ON FUNCTION public.assert_encrypted_category_metadata(TEXT, TEXT, TEXT)
IS 'Internal invariant check for encrypted category name/icon/color metadata; callers must not expose plaintext category structure.';
COMMENT ON FUNCTION public.enforce_encrypted_category_metadata()
IS 'Requires category name/icon/color to be client-side encrypted enc:cat:v1 fields and neutralizes hierarchy/sort metadata.';
