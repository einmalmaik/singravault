-- ===========================================================================
-- Add-Device-Flow: RPCs für Pending Device Requests und Pairing
-- --------------------------------------------------------------------------
-- 
-- 1. create_pending_device_request  - Browser erstellt Pairing-Anfrage
-- 2. get_pending_device_requests     - Tauri liest offene Anfragen
-- 3. approve_pending_device_request - Tauri bestätigt (signiert add_device)
-- 4. reject_pending_device_request  - Tauri lehnt ab
-- ===========================================================================

-- -------------------------------------------------------------------------- 
-- 1. create_pending_device_request
-- --------------------------------------------------------------------------

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
    
    -- Vault-Besitz prüfen
    IF NOT EXISTS (
        SELECT 1 FROM public.vaults
        WHERE id = p_vault_id AND user_id = _uid
    ) THEN
        RAISE EXCEPTION 'Vault does not belong to caller';
    END IF;
    
    -- Prüfen ob Gerät bereits im Trust ist
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
    
    -- Challenge läuft nach 30 Minuten ab
    _challenge_expires_at := NOW() + INTERVAL '30 minutes';
    
    -- Alte Anfrage für dasselbe noch untrusted Gerät löschen.
    -- Ein fehlgeschlagener add_device-Submit darf keine dauerhaft blockierende
    -- approved/rejected-Zeile hinterlassen.
    DELETE FROM public.vault_pending_device_requests
    WHERE vault_id = p_vault_id 
      AND requested_device_id = p_requested_device_id;
    
    -- Neue Anfrage erstellen
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

REVOKE ALL ON FUNCTION public.create_pending_device_request(UUID, UUID, TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_pending_device_request(UUID, UUID, TEXT, TEXT, TEXT, TEXT) TO authenticated;

COMMENT ON FUNCTION public.create_pending_device_request IS
    'Add-Device-Flow: Browser erstellt Pairing-Anfrage. Ersetzt keine alte Anfrage, löscht diese vorher.';

-- -------------------------------------------------------------------------- 
-- 2. get_pending_device_requests
-- --------------------------------------------------------------------------

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
    
    -- Nur offene, nicht abgelaufene und noch nicht getrustete Requests zurückgeben
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

REVOKE ALL ON FUNCTION public.get_pending_device_requests(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_pending_device_requests(UUID) TO authenticated;

COMMENT ON FUNCTION public.get_pending_device_requests IS
    'Add-Device-Flow: Tauri liest offene Pairing-Anfragen. Zeigt nur pending, nicht abgelaufene Requests.';

-- -------------------------------------------------------------------------- 
-- 3. approve_pending_device_request
-- --------------------------------------------------------------------------

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
    
    -- Request laden
    SELECT * INTO _request
    FROM public.vault_pending_device_requests
    WHERE request_id = p_request_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'approved', false,
            'reason', 'request_not_found'
        );
    END IF;
    
    -- Vault-Besitz prüfen
    IF _request.user_id <> _uid THEN
        RAISE EXCEPTION 'Request does not belong to caller';
    END IF;
    
    -- Prüfen ob Request noch nicht abgelaufen
    IF _request.challenge_expires_at <= NOW() THEN
        UPDATE public.vault_pending_device_requests
        SET status = 'expired', updated_at = NOW()
        WHERE request_id = p_request_id;
        
        RETURN jsonb_build_object(
            'approved', false,
            'reason', 'request_expired'
        );
    END IF;
    
    -- Prüfen ob approver im Trust ist
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
    
    -- WICHTIG: Hier wird der Pending Request absichtlich nicht als approved
    -- markiert. Trust entsteht erst durch die nachfolgende, vom Trusted Device
    -- signierte add_device-Operation via submit_vault_operation. Wenn dieser
    -- Submit scheitert, muss der Request retrybar bleiben.
    
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

REVOKE ALL ON FUNCTION public.approve_pending_device_request(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.approve_pending_device_request(UUID, UUID) TO authenticated;

COMMENT ON FUNCTION public.approve_pending_device_request IS
    'Add-Device-Flow: Tauri liest eine bestaetigungsfaehige Pairing-Anfrage. Erzeugt keinen Trust und verbraucht den Request nicht; Client muss signieren und submit_vault_operation aufrufen.';

-- -------------------------------------------------------------------------- 
-- 4. reject_pending_device_request
-- --------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.reject_pending_device_request(
    p_request_id UUID,
    p_rejecter_device_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _request public.vault_pending_device_requests%ROWTYPE;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;
    
    IF p_request_id IS NULL THEN
        RAISE EXCEPTION 'Missing required parameters';
    END IF;
    
    -- Request laden
    SELECT * INTO _request
    FROM public.vault_pending_device_requests
    WHERE request_id = p_request_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'rejected', false,
            'reason', 'request_not_found'
        );
    END IF;
    
    -- Vault-Besitz prüfen
    IF _request.user_id <> _uid THEN
        RAISE EXCEPTION 'Request does not belong to caller';
    END IF;
    
    -- Status aktualisieren
    UPDATE public.vault_pending_device_requests
    SET status = 'rejected',
        resolved_at = NOW(),
        resolved_by_device_id = p_rejecter_device_id,
        updated_at = NOW()
    WHERE request_id = p_request_id;
    
    RETURN jsonb_build_object(
        'rejected', true,
        'request_id', p_request_id
    );
END;
$$;

REVOKE ALL ON FUNCTION public.reject_pending_device_request(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reject_pending_device_request(UUID, UUID) TO authenticated;

COMMENT ON FUNCTION public.reject_pending_device_request IS
    'Add-Device-Flow: Tauri lehnt Pairing-Anfrage ab.';

-- -------------------------------------------------------------------------- 
-- 5. cleanup_expired_requests (optional, für cron)
-- --------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.cleanup_expired_device_requests()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _expired_count INTEGER;
BEGIN
    UPDATE public.vault_pending_device_requests
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'pending' AND challenge_expires_at <= NOW();
    
    GET DIAGNOSTICS _expired_count = ROW_COUNT;
    
    RETURN jsonb_build_object(
        'cleaned_up', _expired_count
    );
END;
$$;

REVOKE ALL ON FUNCTION public.cleanup_expired_device_requests() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cleanup_expired_device_requests() TO authenticated;

COMMENT ON FUNCTION public.cleanup_expired_device_requests IS
    'Add-Device-Flow: Markiert abgelaufene Requests als expired. Sollte periodisch aufgerufen werden.';
