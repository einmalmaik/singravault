-- Align Premium file attachment limits with the chunked E2EE format.
--
-- file_attachments.file_size stores technical ciphertext bytes, not the
-- original plaintext file size. A 1 GB plaintext file can exceed 1 GB in
-- storage because AES-GCM tags and base64 transport add overhead, so the
-- storage quota here is a ciphertext budget.

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

    IF NOT EXISTS (
        SELECT 1
        FROM public.vault_items vi
        WHERE vi.id = NEW.vault_item_id
          AND vi.user_id = NEW.user_id
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
'Enforces owner binding, opaque metadata placeholders, encrypted manifests, owner-prefixed extensionless paths, paid entitlement, and a 2 GB ciphertext budget for 1 GB E2EE file uploads.';
