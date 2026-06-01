-- Allow Premium file attachments to target the current OpLog item records.
--
-- The legacy attachment table was created when vault entries lived in
-- public.vault_items. The current vault runtime stores entries in
-- public.vault_records via signed OpLog operations, so new item ids no longer
-- satisfy the old foreign key. Keep the existing column name for API
-- compatibility, but validate ownership against either the legacy table or an
-- active OpLog item record.

ALTER TABLE public.file_attachments
    DROP CONSTRAINT IF EXISTS file_attachments_vault_item_id_fkey;

COMMENT ON COLUMN public.file_attachments.vault_item_id IS
'Logical vault item id. Legacy rows reference public.vault_items.id; current OpLog rows reference public.vault_records.record_id with record_type=item.';

CREATE OR REPLACE FUNCTION public.enforce_file_attachments_security()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_current_usage BIGINT;
BEGIN
    IF auth.role() = 'service_role' THEN
        RETURN NEW;
    END IF;

    IF NEW.user_id IS NULL THEN
        RAISE EXCEPTION 'user_id is required';
    END IF;

    IF auth.uid() IS DISTINCT FROM NEW.user_id THEN
        RAISE EXCEPTION 'Attachment user_id must match authenticated user';
    END IF;

    IF NEW.file_size IS NULL OR NEW.file_size <= 0 THEN
        RAISE EXCEPTION 'Invalid attachment ciphertext size';
    END IF;

    -- Technical ciphertext budget: supports 1 GB plaintext files with
    -- AES-GCM/base64 overhead while keeping storage bounded.
    IF NEW.file_size > 2147483648 THEN
        RAISE EXCEPTION 'Attachment exceeds 2 GB ciphertext per-file limit';
    END IF;

    IF NOT (
        EXISTS (
            SELECT 1
            FROM public.vault_records vr
            WHERE vr.record_id = NEW.vault_item_id
              AND vr.user_id = NEW.user_id
              AND vr.record_type = 'item'
              AND vr.is_tombstone IS FALSE
        )
        OR EXISTS (
            SELECT 1
            FROM public.vault_items vi
            WHERE vi.id = NEW.vault_item_id
              AND vi.user_id = NEW.user_id
        )
    ) THEN
        RAISE EXCEPTION 'Attachment vault item must belong to authenticated user';
    END IF;

    IF NEW.storage_path IS NULL OR position((NEW.user_id::text || '/') in NEW.storage_path) <> 1 THEN
        RAISE EXCEPTION 'Attachment storage_path must be namespaced by user_id';
    END IF;

    IF NEW.storage_path ~ '\.[A-Za-z0-9]{1,12}$' THEN
        RAISE EXCEPTION 'Attachment storage_path must not contain plaintext file extensions';
    END IF;

    IF COALESCE(NEW.file_name, '') <> 'encrypted' THEN
        RAISE EXCEPTION 'Attachment file_name must be an opaque placeholder';
    END IF;

    IF COALESCE(NEW.mime_type, '') <> 'application/octet-stream' THEN
        RAISE EXCEPTION 'Attachment mime_type must be an opaque placeholder';
    END IF;

    IF NEW.encrypted_metadata IS NULL OR NEW.encrypted_metadata NOT LIKE 'sv-file-manifest-v1:%' THEN
        RAISE EXCEPTION 'Attachment encrypted manifest is required';
    END IF;

    IF COALESCE(NEW.encrypted, FALSE) IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'Attachment must be stored as encrypted content';
    END IF;

    IF TG_OP = 'INSERT' AND NOT public.user_has_active_paid_subscription(NEW.user_id) THEN
        RAISE EXCEPTION 'File attachments require an active Premium or Families subscription';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.user_id::text, 0));

    SELECT COALESCE(SUM(fa.file_size), 0)
      INTO v_current_usage
      FROM public.file_attachments fa
     WHERE fa.user_id = NEW.user_id
       AND (TG_OP <> 'UPDATE' OR fa.id <> NEW.id);

    IF v_current_usage + NEW.file_size > 2147483648 THEN
        RAISE EXCEPTION 'Attachment ciphertext storage limit exceeded (2 GB)';
    END IF;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION public.enforce_file_attachments_security() IS
'Enforces owner binding for legacy vault_items and current OpLog item records, opaque metadata placeholders, encrypted manifests, owner-prefixed extensionless paths, paid entitlement, and a 2 GB ciphertext budget for 1 GB E2EE file uploads.';
