-- ============================================
-- Harden support RLS to permission model
-- ============================================
--
-- Goal:
-- - Remove implicit admin/moderator-wide data access from support table RLS.
-- - Enforce support access by explicit permission keys.
-- - Keep end-user owner access unchanged.

-- ============================================
-- support_tickets policies
-- ============================================

DROP POLICY IF EXISTS "Support tickets select" ON public.support_tickets;
DROP POLICY IF EXISTS "Support tickets insert" ON public.support_tickets;
DROP POLICY IF EXISTS "Support tickets update" ON public.support_tickets;
DROP POLICY IF EXISTS "Support tickets delete" ON public.support_tickets;

CREATE POLICY "Support tickets select"
    ON public.support_tickets FOR SELECT
    TO authenticated
    USING (
        (SELECT auth.uid()) = user_id
        OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.read'))
    );

CREATE POLICY "Support tickets insert"
    ON public.support_tickets FOR INSERT
    TO authenticated
    WITH CHECK (
        (SELECT auth.uid()) = user_id
    );

CREATE POLICY "Support tickets update"
    ON public.support_tickets FOR UPDATE
    TO authenticated
    USING (
        (SELECT auth.uid()) = user_id
        OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    )
    WITH CHECK (
        (SELECT auth.uid()) = user_id
        OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );

CREATE POLICY "Support tickets delete"
    ON public.support_tickets FOR DELETE
    TO authenticated
    USING (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );

-- ============================================
-- support_messages policies
-- ============================================

DROP POLICY IF EXISTS "Support messages select" ON public.support_messages;
DROP POLICY IF EXISTS "Support messages insert" ON public.support_messages;
DROP POLICY IF EXISTS "Support messages update" ON public.support_messages;
DROP POLICY IF EXISTS "Support messages delete" ON public.support_messages;

CREATE POLICY "Support messages select"
    ON public.support_messages FOR SELECT
    TO authenticated
    USING (
        (
            is_internal = false
            AND EXISTS (
                SELECT 1
                FROM public.support_tickets t
                WHERE t.id = support_messages.ticket_id
                  AND t.user_id = (SELECT auth.uid())
            )
        )
        OR (
            (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.read'))
            AND (
                is_internal = false
                OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.reply_internal'))
            )
        )
    );

CREATE POLICY "Support messages insert"
    ON public.support_messages FOR INSERT
    TO authenticated
    WITH CHECK (
        (
            author_role = 'user'
            AND is_internal = false
            AND author_user_id = (SELECT auth.uid())
            AND EXISTS (
                SELECT 1
                FROM public.support_tickets t
                WHERE t.id = support_messages.ticket_id
                  AND t.user_id = (SELECT auth.uid())
            )
        )
        OR (
            author_role = 'support'
            AND author_user_id = (SELECT auth.uid())
            AND (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.reply'))
            AND (
                is_internal = false
                OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.reply_internal'))
            )
        )
    );

CREATE POLICY "Support messages update"
    ON public.support_messages FOR UPDATE
    TO authenticated
    USING (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    )
    WITH CHECK (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );

CREATE POLICY "Support messages delete"
    ON public.support_messages FOR DELETE
    TO authenticated
    USING (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );

-- ============================================
-- support_events policies
-- ============================================

DROP POLICY IF EXISTS "Support events select" ON public.support_events;
DROP POLICY IF EXISTS "Support events insert" ON public.support_events;

CREATE POLICY "Support events select"
    ON public.support_events FOR SELECT
    TO authenticated
    USING (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.metrics.read'))
        OR (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );

CREATE POLICY "Support events insert"
    ON public.support_events FOR INSERT
    TO authenticated
    WITH CHECK (
        (SELECT public.has_permission((SELECT auth.uid()), 'support.tickets.status'))
    );
