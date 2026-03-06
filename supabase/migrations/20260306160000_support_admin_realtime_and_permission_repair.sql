-- ============================================
-- Support/Admin realtime + permission repair
-- ============================================

-- Ensure all support/admin permission keys exist (idempotent).
INSERT INTO public.team_permissions (permission_key, label, description, category)
VALUES
    ('support.admin.access', 'Support Admin Access', 'Access to the internal support admin area.', 'support'),
    ('support.tickets.read', 'Read Support Tickets', 'Read all support tickets and public ticket messages.', 'support'),
    ('support.tickets.reply', 'Reply to Support Tickets', 'Send support replies visible to users.', 'support'),
    ('support.tickets.reply_internal', 'Write Internal Notes', 'Write and view internal support notes.', 'support'),
    ('support.tickets.status', 'Update Ticket Status', 'Change support ticket workflow status.', 'support'),
    ('support.metrics.read', 'Read Support Metrics', 'Read support SLA metrics and response analytics.', 'support'),
    ('support.pii.read', 'Read Support PII', 'Read unmasked requester e-mail addresses in support admin.', 'support'),
    ('subscriptions.read', 'Read Subscriptions', 'Read user subscription data in admin area.', 'subscription'),
    ('subscriptions.manage', 'Manage Subscriptions', 'Manage user subscription data in admin area.', 'subscription'),
    ('team.roles.read', 'Read Team Roles', 'View role assignments for internal team members.', 'team'),
    ('team.roles.manage', 'Manage Team Roles', 'Assign or remove internal team roles.', 'team'),
    ('team.permissions.read', 'Read Role Permissions', 'View permission matrix for roles.', 'team'),
    ('team.permissions.manage', 'Manage Role Permissions', 'Change permission matrix for roles.', 'team')
ON CONFLICT (permission_key) DO UPDATE
SET
    label = EXCLUDED.label,
    description = EXCLUDED.description,
    category = EXCLUDED.category;

-- Ensure admin role keeps full support/admin surface.
INSERT INTO public.role_permissions (role, permission_key)
SELECT 'admin'::app_role, permission_key
FROM public.team_permissions
WHERE permission_key IN (
    'support.admin.access',
    'support.tickets.read',
    'support.tickets.reply',
    'support.tickets.reply_internal',
    'support.tickets.status',
    'support.metrics.read',
    'support.pii.read',
    'subscriptions.read',
    'subscriptions.manage',
    'team.roles.read',
    'team.roles.manage',
    'team.permissions.read',
    'team.permissions.manage'
)
ON CONFLICT (role, permission_key) DO NOTHING;

-- Ensure moderator role keeps support access and read-only team visibility.
INSERT INTO public.role_permissions (role, permission_key)
SELECT 'moderator'::app_role, permission_key
FROM public.team_permissions
WHERE permission_key IN (
    'support.admin.access',
    'support.tickets.read',
    'support.tickets.reply',
    'support.tickets.reply_internal',
    'support.tickets.status',
    'support.metrics.read',
    'team.roles.read',
    'team.permissions.read',
    'subscriptions.read'
)
ON CONFLICT (role, permission_key) DO NOTHING;

-- Ensure support tables are part of the realtime publication.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_publication_tables
            WHERE pubname = 'supabase_realtime'
              AND schemaname = 'public'
              AND tablename = 'support_tickets'
        ) THEN
            ALTER PUBLICATION supabase_realtime ADD TABLE public.support_tickets;
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_publication_tables
            WHERE pubname = 'supabase_realtime'
              AND schemaname = 'public'
              AND tablename = 'support_messages'
        ) THEN
            ALTER PUBLICATION supabase_realtime ADD TABLE public.support_messages;
        END IF;
    END IF;
END $$;
