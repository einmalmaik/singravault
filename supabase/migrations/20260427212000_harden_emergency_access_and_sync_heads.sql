-- Harden remaining emergency-access boundaries and add monotonic vault sync heads.
--
-- This migration is intentionally narrow:
-- - Emergency Access keeps the existing table and status model, but removes
--   duplicate broad policies and blocks legacy key material on future writes.
-- - Vault sync heads provide a server-maintained monotonic revision that clients
--   can compare with their last trusted local checkpoint to detect stale reads.

-- ---------------------------------------------------------------------------
-- Emergency Access: one policy per role/action and no legacy wrapped key writes.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.validate_emergency_access_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    is_grantor BOOLEAN;
    is_trustee BOOLEAN;
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RETURN NEW;
    END IF;

    -- RSA-only emergency key material is no longer accepted for new writes.
    IF NEW.encrypted_master_key IS NOT NULL THEN
        RAISE EXCEPTION 'Legacy emergency access key material is disabled';
    END IF;

    IF NEW.grantor_id IS DISTINCT FROM OLD.grantor_id THEN
        RAISE EXCEPTION 'Cannot change grantor_id';
    END IF;

    is_grantor := auth.uid() = OLD.grantor_id;
    is_trustee := auth.uid() = OLD.trusted_user_id
        OR (
            OLD.trusted_user_id IS NULL
            AND lower(OLD.trusted_email) = lower(current_setting('request.jwt.claim.email', true))
            AND NEW.trusted_user_id = auth.uid()
        );

    IF NOT is_grantor AND NOT is_trustee THEN
        RAISE EXCEPTION 'Unauthorized emergency access transition';
    END IF;

    IF is_grantor THEN
        IF NEW.trusted_user_id IS DISTINCT FROM OLD.trusted_user_id THEN
            RAISE EXCEPTION 'Grantors cannot relink trusted_user_id; revoke and invite again';
        END IF;

        IF OLD.status IN ('pending', 'granted') AND NEW.wait_days IS DISTINCT FROM OLD.wait_days THEN
            RAISE EXCEPTION 'Cannot change wait_days while access is pending or granted';
        END IF;

        IF NEW.status = 'granted' THEN
            IF NEW.trusted_user_id IS NULL THEN
                RAISE EXCEPTION 'Cannot grant emergency access before trustee acceptance';
            END IF;
            IF NEW.pq_encrypted_master_key IS NULL THEN
                RAISE EXCEPTION 'Cannot grant emergency access without hybrid key material';
            END IF;
            NEW.granted_at = COALESCE(NEW.granted_at, NOW());
        END IF;

        IF NEW.status IN ('pending', 'rejected', 'expired') AND NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION 'Grantors cannot set granted_at for non-granted states';
        END IF;

        RETURN NEW;
    END IF;

    IF is_trustee THEN
        IF NEW.wait_days IS DISTINCT FROM OLD.wait_days THEN
            RAISE EXCEPTION 'Trustees cannot change wait_days';
        END IF;
        IF NEW.trusted_email IS DISTINCT FROM OLD.trusted_email THEN
            RAISE EXCEPTION 'Trustees cannot change trusted_email';
        END IF;
        IF NEW.pq_encrypted_master_key IS DISTINCT FROM OLD.pq_encrypted_master_key THEN
            RAISE EXCEPTION 'Trustees cannot change emergency key material';
        END IF;

        IF OLD.trusted_user_id IS NOT NULL THEN
            IF NEW.trusted_user_id IS DISTINCT FROM OLD.trusted_user_id THEN
                RAISE EXCEPTION 'Trustees cannot relink trusted_user_id';
            END IF;
            IF NEW.trustee_public_key IS DISTINCT FROM OLD.trustee_public_key THEN
                RAISE EXCEPTION 'Trustees cannot change trustee_public_key after acceptance';
            END IF;
            IF NEW.trustee_pq_public_key IS DISTINCT FROM OLD.trustee_pq_public_key THEN
                RAISE EXCEPTION 'Trustees cannot change trustee_pq_public_key after acceptance';
            END IF;
        END IF;

        IF NEW.status IS DISTINCT FROM OLD.status THEN
            IF OLD.status = 'invited' AND NEW.status = 'accepted' THEN
                IF NEW.trusted_user_id IS NULL THEN
                    RAISE EXCEPTION 'Trustee must link their user account when accepting';
                END IF;
                IF NEW.trustee_public_key IS NULL OR NEW.trustee_pq_public_key IS NULL THEN
                    RAISE EXCEPTION 'Trustee acceptance requires RSA and PQ public keys';
                END IF;
                IF NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN
                    RAISE EXCEPTION 'Trustees cannot change requested_at during acceptance';
                END IF;
                IF NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
                    RAISE EXCEPTION 'Trustees cannot change granted_at during acceptance';
                END IF;
                RETURN NEW;
            ELSIF OLD.status = 'accepted' AND NEW.status = 'pending' THEN
                NEW.requested_at = NOW();
                RETURN NEW;
            ELSIF OLD.status = 'pending' AND NEW.status = 'granted' THEN
                IF OLD.requested_at IS NULL THEN
                    RAISE EXCEPTION 'Requested at timestamp is missing';
                END IF;
                IF OLD.requested_at + (OLD.wait_days || ' days')::interval > NOW() THEN
                    RAISE EXCEPTION 'Access cooldown period has not expired yet';
                END IF;
                IF NEW.pq_encrypted_master_key IS NULL THEN
                    RAISE EXCEPTION 'Cannot grant emergency access without hybrid key material';
                END IF;
                NEW.granted_at = NOW();
                RETURN NEW;
            ELSIF NEW.status = 'rejected' THEN
                RETURN NEW;
            END IF;

            RAISE EXCEPTION 'Trustee not allowed to transition status from % to %', OLD.status, NEW.status;
        END IF;

        IF NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN
            RAISE EXCEPTION 'Trustees cannot change requested_at without status transition';
        END IF;
        IF NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION 'Trustees cannot change granted_at without status transition';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS validate_emergency_access_transition_trigger ON public.emergency_access;
CREATE TRIGGER validate_emergency_access_transition_trigger
    BEFORE UPDATE ON public.emergency_access
    FOR EACH ROW
    EXECUTE FUNCTION public.validate_emergency_access_transition();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'emergency_access_no_legacy_master_key_check'
          AND conrelid = 'public.emergency_access'::regclass
    ) THEN
        ALTER TABLE public.emergency_access
        ADD CONSTRAINT emergency_access_no_legacy_master_key_check
        CHECK (encrypted_master_key IS NULL)
        NOT VALID;
    END IF;
END $$;

DROP POLICY IF EXISTS "Grantors can update emergency access" ON public.emergency_access;
DROP POLICY IF EXISTS "Users can update own emergency access as grantor" ON public.emergency_access;
DROP POLICY IF EXISTS "Users can insert own emergency access as grantor" ON public.emergency_access;
DROP POLICY IF EXISTS "Users can view own emergency access as grantor" ON public.emergency_access;
DROP POLICY IF EXISTS "Grantors can view own emergency access" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can accept invite - hardened" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can accept invite" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can update linked emergency access" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can view emergency access" ON public.emergency_access;
DROP POLICY IF EXISTS "Emergency access visible to participants" ON public.emergency_access;
DROP POLICY IF EXISTS "Grantors can update own emergency access" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can accept emergency invite" ON public.emergency_access;
DROP POLICY IF EXISTS "Trustees can progress linked emergency access" ON public.emergency_access;

CREATE POLICY "Emergency access visible to participants"
    ON public.emergency_access FOR SELECT
    TO authenticated
    USING (
        auth.uid() = grantor_id
        OR auth.uid() = trusted_user_id
        OR (
            trusted_user_id IS NULL
            AND lower(trusted_email) = lower(current_setting('request.jwt.claim.email', true))
        )
    );

CREATE POLICY "Grantors can update own emergency access"
    ON public.emergency_access FOR UPDATE
    TO authenticated
    USING (auth.uid() = grantor_id)
    WITH CHECK (auth.uid() = grantor_id);

CREATE POLICY "Trustees can accept emergency invite"
    ON public.emergency_access FOR UPDATE
    TO authenticated
    USING (
        trusted_user_id IS NULL
        AND lower(trusted_email) = lower(current_setting('request.jwt.claim.email', true))
    )
    WITH CHECK (
        trusted_user_id = auth.uid()
        AND status = 'accepted'
    );

CREATE POLICY "Trustees can progress linked emergency access"
    ON public.emergency_access FOR UPDATE
    TO authenticated
    USING (auth.uid() = trusted_user_id)
    WITH CHECK (
        auth.uid() = trusted_user_id
        AND status IN ('pending', 'granted', 'rejected', 'accepted')
    );

DROP POLICY IF EXISTS "Trustees can view vault items of grantors" ON public.vault_items;
DROP POLICY IF EXISTS "Trustees can view granted emergency vault items" ON public.vault_items;
CREATE POLICY "Trustees can view granted emergency vault items"
    ON public.vault_items FOR SELECT
    TO authenticated
    USING (
        EXISTS (
            SELECT 1
            FROM public.emergency_access ea
            WHERE ea.grantor_id = vault_items.user_id
              AND ea.trusted_user_id = auth.uid()
              AND ea.status = 'granted'
              AND ea.granted_at IS NOT NULL
              AND ea.pq_encrypted_master_key IS NOT NULL
        )
    );

-- ---------------------------------------------------------------------------
-- Vault sync heads: monotonic per-vault revision for local rollback detection.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.vault_sync_heads (
    vault_id UUID PRIMARY KEY REFERENCES public.vaults(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

ALTER TABLE public.vault_sync_heads ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own vault sync heads" ON public.vault_sync_heads;
CREATE POLICY "Users can view own vault sync heads"
    ON public.vault_sync_heads FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.bump_vault_sync_head(
    p_vault_id UUID,
    p_user_id UUID
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    next_revision BIGINT;
BEGIN
    IF p_vault_id IS NULL OR p_user_id IS NULL THEN
        RETURN NULL;
    END IF;

    INSERT INTO public.vault_sync_heads (vault_id, user_id, revision, updated_at)
    VALUES (p_vault_id, p_user_id, 1, NOW())
    ON CONFLICT (vault_id) DO UPDATE
    SET revision = public.vault_sync_heads.revision + 1,
        updated_at = NOW()
    RETURNING revision INTO next_revision;

    RETURN next_revision;
END;
$$;

CREATE OR REPLACE FUNCTION public.bump_vault_item_sync_head()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    target_vault_id UUID;
    target_user_id UUID;
BEGIN
    target_vault_id := COALESCE(NEW.vault_id, OLD.vault_id);
    target_user_id := COALESCE(NEW.user_id, OLD.user_id);
    PERFORM public.bump_vault_sync_head(target_vault_id, target_user_id);
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION public.bump_category_sync_head()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    target_vault_id UUID;
    target_user_id UUID;
BEGIN
    target_user_id := COALESCE(NEW.user_id, OLD.user_id);

    SELECT id INTO target_vault_id
    FROM public.vaults
    WHERE user_id = target_user_id
      AND is_default = true
    ORDER BY created_at ASC
    LIMIT 1;

    PERFORM public.bump_vault_sync_head(target_vault_id, target_user_id);
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS bump_vault_item_sync_head_trigger ON public.vault_items;
CREATE TRIGGER bump_vault_item_sync_head_trigger
    AFTER INSERT OR UPDATE OR DELETE ON public.vault_items
    FOR EACH ROW
    EXECUTE FUNCTION public.bump_vault_item_sync_head();

DROP TRIGGER IF EXISTS bump_category_sync_head_trigger ON public.categories;
CREATE TRIGGER bump_category_sync_head_trigger
    AFTER INSERT OR UPDATE OR DELETE ON public.categories
    FOR EACH ROW
    EXECUTE FUNCTION public.bump_category_sync_head();

INSERT INTO public.vault_sync_heads (vault_id, user_id, revision, updated_at)
SELECT v.id, v.user_id, 1, NOW()
FROM public.vaults v
WHERE EXISTS (
    SELECT 1
    FROM public.vault_items vi
    WHERE vi.vault_id = v.id
)
ON CONFLICT (vault_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.get_vault_sync_head(p_vault_id UUID)
RETURNS TABLE(vault_id UUID, user_id UUID, revision BIGINT, updated_at TIMESTAMP WITH TIME ZONE)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT h.vault_id, h.user_id, h.revision, h.updated_at
    FROM public.vault_sync_heads h
    WHERE h.vault_id = p_vault_id
      AND h.user_id = auth.uid();
$$;

REVOKE ALL ON FUNCTION public.bump_vault_sync_head(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.bump_vault_item_sync_head() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_vault_sync_head(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_vault_sync_head(UUID) TO authenticated;

CREATE OR REPLACE FUNCTION public.apply_vault_mutation(
    p_base_revision BIGINT,
    p_type TEXT,
    p_payload JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    _uid UUID := auth.uid();
    _vault_id UUID;
    _current_revision BIGINT := 0;
    _next_revision BIGINT := 0;
    _item_id UUID;
    _category_id UUID;
BEGIN
    IF _uid IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    IF p_type NOT IN ('upsert_item', 'delete_item', 'upsert_category', 'delete_category') THEN
        RAISE EXCEPTION 'Unsupported vault mutation type';
    END IF;

    IF p_type IN ('upsert_item', 'delete_item') THEN
        _item_id := (p_payload->>'id')::UUID;
        IF p_type = 'upsert_item' THEN
            _vault_id := (p_payload->>'vault_id')::UUID;
            IF (p_payload->>'user_id')::UUID IS DISTINCT FROM _uid THEN
                RAISE EXCEPTION 'Mutation user_id must match authenticated user';
            END IF;
            IF NOT EXISTS (
                SELECT 1
                FROM public.vaults
                WHERE id = _vault_id
                  AND user_id = _uid
            ) THEN
                RAISE EXCEPTION 'Mutation vault_id must belong to authenticated user';
            END IF;
        ELSE
            SELECT vault_id INTO _vault_id
            FROM public.vault_items
            WHERE id = _item_id
              AND user_id = _uid;
        END IF;
    ELSE
        _category_id := (p_payload->>'id')::UUID;
        IF p_type = 'upsert_category' AND (p_payload->>'user_id')::UUID IS DISTINCT FROM _uid THEN
            RAISE EXCEPTION 'Mutation user_id must match authenticated user';
        END IF;

        SELECT id INTO _vault_id
        FROM public.vaults
        WHERE user_id = _uid
          AND is_default = true
        ORDER BY created_at ASC
        LIMIT 1;
    END IF;

    IF _vault_id IS NULL THEN
        RETURN jsonb_build_object('applied', false, 'conflict_reason', 'missing_vault');
    END IF;

    INSERT INTO public.vault_sync_heads (vault_id, user_id, revision, updated_at)
    VALUES (_vault_id, _uid, 0, NOW())
    ON CONFLICT (vault_id) DO NOTHING;

    SELECT revision INTO _current_revision
    FROM public.vault_sync_heads
    WHERE vault_id = _vault_id
      AND user_id = _uid
    FOR UPDATE;

    IF p_base_revision IS NOT NULL AND _current_revision <> p_base_revision THEN
        RETURN jsonb_build_object(
            'applied', false,
            'revision', _current_revision,
            'conflict_reason', 'stale_base_revision'
        );
    END IF;

    IF p_type = 'upsert_item' THEN
        INSERT INTO public.vault_items (
            id,
            user_id,
            vault_id,
            title,
            website_url,
            icon_url,
            item_type,
            encrypted_data,
            category_id,
            is_favorite,
            sort_order,
            last_used_at
        )
        VALUES (
            _item_id,
            _uid,
            _vault_id,
            COALESCE(p_payload->>'title', 'Encrypted Item'),
            p_payload->>'website_url',
            p_payload->>'icon_url',
            COALESCE(p_payload->>'item_type', 'password')::public.vault_item_type,
            p_payload->>'encrypted_data',
            NULLIF(p_payload->>'category_id', '')::UUID,
            COALESCE((p_payload->>'is_favorite')::BOOLEAN, false),
            NULLIF(p_payload->>'sort_order', '')::INTEGER,
            NULLIF(p_payload->>'last_used_at', '')::TIMESTAMPTZ
        )
        ON CONFLICT (id) DO UPDATE
        SET encrypted_data = EXCLUDED.encrypted_data,
            updated_at = NOW();
    ELSIF p_type = 'delete_item' THEN
        DELETE FROM public.vault_items
        WHERE id = _item_id
          AND user_id = _uid;
    ELSIF p_type = 'upsert_category' THEN
        IF COALESCE(p_payload->>'name', '') NOT LIKE 'enc:cat:v1:%' THEN
            RAISE EXCEPTION 'Category name must be client-side encrypted'
                USING ERRCODE = '22023';
        END IF;

        IF p_payload ? 'icon'
           AND p_payload->>'icon' IS NOT NULL
           AND p_payload->>'icon' NOT LIKE 'enc:cat:v1:%' THEN
            RAISE EXCEPTION 'Category icon must be client-side encrypted'
                USING ERRCODE = '22023';
        END IF;

        IF p_payload ? 'color'
           AND p_payload->>'color' IS NOT NULL
           AND p_payload->>'color' NOT LIKE 'enc:cat:v1:%' THEN
            RAISE EXCEPTION 'Category color must be client-side encrypted'
                USING ERRCODE = '22023';
        END IF;

        INSERT INTO public.categories (
            id,
            user_id,
            name,
            icon,
            color,
            parent_id,
            sort_order
        )
        VALUES (
            _category_id,
            _uid,
            p_payload->>'name',
            p_payload->>'icon',
            p_payload->>'color',
            NULL,
            NULL
        )
        ON CONFLICT (id) DO UPDATE
        SET name = EXCLUDED.name,
            icon = EXCLUDED.icon,
            color = EXCLUDED.color,
            parent_id = NULL,
            sort_order = NULL,
            updated_at = NOW();
    ELSIF p_type = 'delete_category' THEN
        DELETE FROM public.categories
        WHERE id = _category_id
          AND user_id = _uid;
    END IF;

    SELECT revision INTO _next_revision
    FROM public.vault_sync_heads
    WHERE vault_id = _vault_id
      AND user_id = _uid;

    RETURN jsonb_build_object(
        'applied', true,
        'revision', COALESCE(_next_revision, _current_revision),
        'conflict_reason', NULL
    );
END;
$$;

REVOKE ALL ON FUNCTION public.apply_vault_mutation(BIGINT, TEXT, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.apply_vault_mutation(BIGINT, TEXT, JSONB) TO authenticated;

COMMENT ON TABLE public.vault_sync_heads IS
    'Server-maintained monotonic per-vault revision. Clients compare it with a locally stored checkpoint to detect stale or rolled-back sync responses on known devices.';
COMMENT ON FUNCTION public.get_vault_sync_head(UUID) IS
    'Returns the caller-owned vault sync revision used for client-side stale/rollback detection.';
COMMENT ON FUNCTION public.apply_vault_mutation(BIGINT, TEXT, JSONB) IS
    'Applies one offline vault mutation only when the client base revision matches the current server sync head.';
