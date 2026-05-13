-- Guard submit_vault_operation against revoked or unknown author devices.
--
-- The client still verifies signatures and the OpLog remains the trust source
-- of truth. This trigger prevents a stale authenticated session on a revoked
-- device from advancing the server-side transport head with operations that
-- every honest client would later reject.

CREATE OR REPLACE FUNCTION public.guard_vault_operation_author_trust()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _author_trust public.vault_device_trust_records%ROWTYPE;
BEGIN
    -- Recovery-code redemption has its own service-role RPC and deliberately
    -- creates trust for the recovered device in the same transaction.
    IF NEW.op_type = 'recover_device' THEN
        RETURN NEW;
    END IF;

    SELECT * INTO _author_trust
    FROM public.vault_device_trust_records
    WHERE vault_id = NEW.vault_id
      AND user_id = NEW.user_id
      AND device_id = NEW.author_device_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'author_device_not_trusted';
    END IF;

    IF _author_trust.status <> 'trusted' THEN
        RAISE EXCEPTION 'author_device_not_trusted';
    END IF;

    IF COALESCE(_author_trust.trust_epoch, 0) <> COALESCE(NEW.trust_epoch, 0) THEN
        RAISE EXCEPTION 'author_device_trust_epoch_mismatch';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS guard_vault_operation_author_trust_trigger ON public.vault_operations;
CREATE TRIGGER guard_vault_operation_author_trust_trigger
BEFORE INSERT ON public.vault_operations
FOR EACH ROW
EXECUTE FUNCTION public.guard_vault_operation_author_trust();

REVOKE ALL ON FUNCTION public.guard_vault_operation_author_trust() FROM PUBLIC;
