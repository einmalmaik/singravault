-- Enforce client-side encrypted category metadata for future writes.
-- Existing legacy plaintext rows are migrated by the client after unlock, because
-- SQL cannot encrypt them without the user's vault key.

CREATE OR REPLACE FUNCTION public.enforce_encrypted_category_metadata()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    IF COALESCE(NEW.name, '') NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category name must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;

    IF NEW.icon IS NOT NULL AND NEW.icon NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category icon must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;

    IF NEW.color IS NOT NULL AND NEW.color NOT LIKE 'enc:cat:v1:%' THEN
        RAISE EXCEPTION 'Category color must be client-side encrypted'
            USING ERRCODE = '22023';
    END IF;

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

COMMENT ON FUNCTION public.enforce_encrypted_category_metadata()
IS 'Requires category name/icon/color to be client-side encrypted enc:cat:v1 fields and neutralizes hierarchy/sort metadata.';
