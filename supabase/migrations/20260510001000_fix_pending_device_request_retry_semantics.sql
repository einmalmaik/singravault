-- ===========================================================================
-- Add-Device-Flow: retry-safe pending request RPC semantics
-- ---------------------------------------------------------------------------
-- Pending requests are not trust. Approving a request must only validate and
-- return the device data for the signed add_device operation. If the later
-- submit_vault_operation call fails, the pending request must remain retryable.
-- ===========================================================================

CREATE OR REPLACE FUNCTION public.create_pending_device_request(
    p_vault_id UUID,
    p_requested_device_id UUID,
    p_requested_device_name TEXT,
    p_requested_public_signing_key TEXT,
    p_requested_device_platform TEXT,
    p_pairing_nonce TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _request_id UUID;
    _challenge_expires_at TIMESTAMPTZ;
    _existing_device public.vault_device_trust_records%ROWTYPE;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_vault_id IS NULL OR p_requested_device_id IS NULL
       OR p_requested_device_name IS NULL OR p_requested_public_signing_key IS NULL
       OR p_pairing_nonce IS NULL THEN
        RAISE EXCEPTION 'Missing required parameters';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;

    SELECT * INTO _existing_device
    FROM public.vault_device_trust_records
    WHERE vault_id = p_vault_id AND device_id = p_requested_device_id;

    IF FOUND AND _existing_device.status = 'trusted' THEN
        RETURN jsonb_build_object(
            'created', false,
            'reason', 'device_already_trusted',
            'request_id', NULL
        );
    END IF;

    _challenge_expires_at := NOW() + INTERVAL '30 minutes';

    DELETE FROM public.vault_pending_device_requests
    WHERE vault_id = p_vault_id
      AND requested_device_id = p_requested_device_id;

    INSERT INTO public.vault_pending_device_requests (
        vault_id, user_id, requested_device_id, requested_device_name,
        requested_public_signing_key, requested_device_platform,
        pairing_nonce, challenge_expires_at, status
    )
    VALUES (
        p_vault_id, _uid, p_requested_device_id, p_requested_device_name,
        p_requested_public_signing_key, p_requested_device_platform,
        p_pairing_nonce, _challenge_expires_at, 'pending'
    )
    RETURNING request_id INTO _request_id;

    RETURN jsonb_build_object(
        'created', true,
        'request_id', _request_id,
        'expires_at', _challenge_expires_at
    );
END;
$$;

CREATE OR REPLACE FUNCTION public.get_pending_device_requests(
    p_vault_id UUID
)
RETURNS TABLE(
    request_id UUID,
    requested_device_id UUID,
    requested_device_name TEXT,
    requested_public_signing_key TEXT,
    requested_device_platform TEXT,
    pairing_nonce TEXT,
    challenge_created_at TIMESTAMPTZ,
    challenge_expires_at TIMESTAMPTZ,
    status TEXT,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
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

    RETURN QUERY
    SELECT
        r.request_id,
        r.requested_device_id,
        r.requested_device_name,
        r.requested_public_signing_key,
        r.requested_device_platform,
        r.pairing_nonce,
        r.challenge_created_at,
        r.challenge_expires_at,
        r.status,
        r.created_at
    FROM public.vault_pending_device_requests r
    WHERE r.vault_id = p_vault_id
      AND r.user_id = _uid
      AND r.status = 'pending'
      AND r.challenge_expires_at > NOW()
      AND NOT EXISTS (
          SELECT 1
          FROM public.vault_device_trust_records d
          WHERE d.vault_id = r.vault_id
            AND d.device_id = r.requested_device_id
            AND d.status = 'trusted'
      );
END;
$$;

CREATE OR REPLACE FUNCTION public.approve_pending_device_request(
    p_request_id UUID,
    p_approver_device_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _request public.vault_pending_device_requests%ROWTYPE;
    _existing_trust public.vault_device_trust_records%ROWTYPE;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_request_id IS NULL OR p_approver_device_id IS NULL THEN
        RAISE EXCEPTION 'Missing required parameters';
    END IF;

    SELECT * INTO _request
    FROM public.vault_pending_device_requests
    WHERE request_id = p_request_id AND status = 'pending';

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'approved', false,
            'reason', 'request_not_found'
        );
    END IF;

    IF _request.user_id <> _uid THEN
        RAISE EXCEPTION 'Request does not belong to caller';
    END IF;

    IF _request.challenge_expires_at <= NOW() THEN
        UPDATE public.vault_pending_device_requests
        SET status = 'expired', updated_at = NOW()
        WHERE request_id = p_request_id;

        RETURN jsonb_build_object(
            'approved', false,
            'reason', 'request_expired'
        );
    END IF;

    SELECT * INTO _existing_trust
    FROM public.vault_device_trust_records
    WHERE vault_id = _request.vault_id
      AND device_id = p_approver_device_id
      AND status = 'trusted';

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'approved', false,
            'reason', 'approver_not_trusted'
        );
    END IF;

    RETURN jsonb_build_object(
        'approved', true,
        'request_id', p_request_id,
        'requested_device_id', _request.requested_device_id,
        'requested_public_signing_key', _request.requested_public_signing_key,
        'requested_device_name', _request.requested_device_name,
        'vault_id', _request.vault_id
    );
END;
$$;

COMMENT ON FUNCTION public.approve_pending_device_request IS
    'Add-Device-Flow: validates a trusted approver and returns pending request data. Does not create trust and does not consume the request.';
