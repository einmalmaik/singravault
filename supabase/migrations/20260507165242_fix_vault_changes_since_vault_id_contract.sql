-- Phase 12 migration recovery contract fix:
-- get_vault_changes_since is used to reload already committed migration
-- operations after an interrupted legacy-to-OpLog migration. The client
-- verifies every returned operation locally and requires vault_id as part of
-- the security-relevant row contract.

DROP FUNCTION IF EXISTS public.get_vault_changes_since(UUID, BIGINT, INTEGER);

CREATE FUNCTION public.get_vault_changes_since(
    p_vault_id UUID,
    p_since_sequence BIGINT,
    p_limit INTEGER
)
RETURNS TABLE(
    vault_id UUID,
    op_id UUID,
    op_hash TEXT,
    sequence_number BIGINT,
    author_device_id UUID,
    op_type TEXT,
    record_id UUID,
    record_type TEXT,
    base_record_version BIGINT,
    previous_ciphertext_hash TEXT,
    new_record_hash TEXT,
    intent_id UUID,
    rebased_from_op_id UUID,
    base_vault_head TEXT,
    resulting_vault_head TEXT,
    payload_ciphertext_hash TEXT,
    payload_aad_hash TEXT,
    signed_body JSONB,
    signature TEXT,
    signature_schema TEXT,
    trust_epoch BIGINT,
    created_at_client TIMESTAMPTZ,
    received_at_server TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _limit INTEGER := COALESCE(p_limit, 500);
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

    IF _limit < 1 OR _limit > 1000 THEN
        RAISE EXCEPTION 'p_limit must be between 1 and 1000';
    END IF;

    RETURN QUERY
    SELECT o.vault_id, o.op_id, o.op_hash, o.sequence_number,
           o.author_device_id, o.op_type, o.record_id, o.record_type,
           o.base_record_version, o.previous_ciphertext_hash,
           o.new_record_hash, o.intent_id, o.rebased_from_op_id,
           o.base_vault_head, o.resulting_vault_head,
           o.payload_ciphertext_hash, o.payload_aad_hash, o.signed_body,
           o.signature, o.signature_schema, o.trust_epoch,
           o.created_at_client, o.received_at_server
    FROM public.vault_operations o
    WHERE o.vault_id = p_vault_id
      AND o.user_id = _uid
      AND o.sequence_number > COALESCE(p_since_sequence, 0)
    ORDER BY o.sequence_number ASC
    LIMIT _limit;
END;
$$;

REVOKE ALL ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) TO authenticated;

COMMENT ON FUNCTION public.get_vault_changes_since(UUID, BIGINT, INTEGER) IS
    'Operation-log Phase 12 fix: returns operations newer than p_since_sequence including vault_id so clients can verify and resume interrupted migrations without reconstructing sealed records.';
