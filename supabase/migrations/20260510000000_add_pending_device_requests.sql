-- ===========================================================================
-- Add-Device-Flow: Pending Device Requests
-- --------------------------------------------------------------------------
-- Diese Tabelle speichert Pairing-Anfragen, wenn ein neues Gerät (Browser)
-- dem Vault hinzugefügt werden möchte. Sie ist VORÜBERGEHEND und bedeutet
-- NICHT automatisch Trust.
--
-- Flow:
--   1. Browser erstellt Pending Request mit eigenem Public Signing Key
--   2. Tauri sieht Request und bestätigt oder lehnt ab
--   3. Bei Bestätigung: add_device Operation via submit_vault_operation
--   4. Browser wird nach Sync erst dann trusted
-- ===========================================================================

CREATE TABLE IF NOT EXISTS public.vault_pending_device_requests (
    -- Primärschlüssel
    request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Vault und Nutzer
    vault_id UUID NOT NULL REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    
    -- Anforderndes Gerät
    requested_device_id UUID NOT NULL,
    requested_device_name TEXT NOT NULL,
    requested_public_signing_key TEXT NOT NULL,
    requested_device_platform TEXT, -- z.B. 'web', 'tauri', 'mobile'
    
    -- Pairing-Challenge
    pairing_nonce TEXT NOT NULL, -- Einmalige Nonce für Replay-Schutz
    challenge_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    challenge_expires_at TIMESTAMPTZ NOT NULL, -- Ablaufzeit der Anfrage
    
    -- Status
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'approved', 'rejected', 'expired')
    ),
    
    -- Ergebnis (wenn genehmigt/abgelehnt)
    resolved_at TIMESTAMPTZ,
    resolved_by_device_id UUID, -- Gerät das approve/reject ausgeführt hat
    
    -- Serverseitige Metadaten
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT vault_pending_device_requests_vault_user_unique_idx UNIQUE (vault_id, requested_device_id),
    CONSTRAINT vault_pending_device_requests_expires_check CHECK (
        challenge_expires_at > NOW()
    )
);

-- Index für effiziente Abfragen
CREATE INDEX IF NOT EXISTS vault_pending_device_requests_vault_idx
    ON public.vault_pending_device_requests(vault_id, status)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS vault_pending_device_requests_user_idx
    ON public.vault_pending_device_requests(user_id, status);

CREATE INDEX IF NOT EXISTS vault_pending_device_requests_expires_idx
    ON public.vault_pending_device_requests(challenge_expires_at)
    WHERE status = 'pending';

-- RLS aktivieren
ALTER TABLE public.vault_pending_device_requests ENABLE ROW LEVEL SECURITY;

-- Nur eigene Vault-Requests lesen
DROP POLICY IF EXISTS "vault_pending_device_requests select own" ON public.vault_pending_device_requests;
CREATE POLICY "vault_pending_device_requests select own"
    ON public.vault_pending_device_requests
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

-- Direkte INSERTs verbieten (nur via RPC)
DROP POLICY IF EXISTS "vault_pending_device_requests deny direct insert" ON public.vault_pending_device_requests;
CREATE POLICY "vault_pending_device_requests deny direct insert"
    ON public.vault_pending_device_requests
    FOR INSERT
    TO authenticated
    WITH CHECK (false);

-- Direkte UPDATEs verbieten (nur via RPC)
DROP POLICY IF EXISTS "vault_pending_device_requests deny direct update" ON public.vault_pending_device_requests;
CREATE POLICY "vault_pending_device_requests deny direct update"
    ON public.vault_pending_device_requests
    FOR UPDATE
    TO authenticated
    USING (false)
    WITH CHECK (false);

-- Direkte DELETEs verbieten
DROP POLICY IF EXISTS "vault_pending_device_requests deny direct delete" ON public.vault_pending_device_requests;
CREATE POLICY "vault_pending_device_requests deny direct delete"
    ON public.vault_pending_device_requests
    FOR DELETE
    TO authenticated
    USING (false);

-- Rechte entziehen
REVOKE INSERT, UPDATE, DELETE ON public.vault_pending_device_requests FROM authenticated;
GRANT SELECT ON public.vault_pending_device_requests TO authenticated;

COMMENT ON TABLE public.vault_pending_device_requests IS
    'Add-Device-Flow: Temporäre Pairing-Anfragen. Kein Trust! Nur via create_pending_device_request RPC erzeugbar.';
