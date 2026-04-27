-- Enforce neutral server-visible vault item metadata for all future writes.
--
-- Existing legacy rows are intentionally not bulk-wiped here because SQL cannot
-- decrypt encrypted_data. The client migration/re-encryption paths must first
-- copy any remaining legacy plaintext metadata into encrypted_data.

CREATE OR REPLACE FUNCTION public.enforce_opaque_vault_item_metadata()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.title := 'Encrypted Item';
    NEW.website_url := NULL;
    NEW.icon_url := NULL;
    NEW.item_type := 'password';
    NEW.is_favorite := false;
    NEW.category_id := NULL;
    NEW.sort_order := NULL;
    NEW.last_used_at := NULL;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_opaque_vault_item_metadata_trigger ON public.vault_items;
CREATE TRIGGER enforce_opaque_vault_item_metadata_trigger
    BEFORE INSERT OR UPDATE ON public.vault_items
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_opaque_vault_item_metadata();

COMMENT ON FUNCTION public.enforce_opaque_vault_item_metadata() IS
    'Forces server-visible vault item metadata to neutral placeholders. Real item metadata belongs in encrypted_data.';
