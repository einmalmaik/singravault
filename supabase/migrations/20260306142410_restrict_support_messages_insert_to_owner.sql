-- ============================================
-- Restrict direct support_messages insert to owner writes
-- ============================================
--
-- Support-team replies are expected to go through the admin-support edge
-- function (service_role). Direct authenticated inserts stay owner-only.

DROP POLICY IF EXISTS "Support messages insert" ON public.support_messages;

CREATE POLICY "Support messages insert"
    ON public.support_messages FOR INSERT
    TO authenticated
    WITH CHECK (
        author_role = 'user'
        AND is_internal = false
        AND author_user_id = (SELECT auth.uid())
        AND EXISTS (
            SELECT 1
            FROM public.support_tickets t
            WHERE t.id = support_messages.ticket_id
              AND t.user_id = (SELECT auth.uid())
        )
    );
