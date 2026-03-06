# Support System

## Overview

Singra Vault includes an in-app support system with SLA targets by plan tier:

- **FREE**: standard support, usually within **72h**
- **PREMIUM**: priority support, usually within **24h**
- **FAMILIES**: priority support, usually within **24h** for owner and all active family members

SLA values are tracked as **target times** ("in der Regel"), not hard legal guarantees.

## Architecture

### Database

Support data is stored in:

- `support_tickets`
- `support_messages`
- `support_events`

Core fields for SLA tracking:

- `sla_hours`
- `sla_due_at`
- `first_response_at`
- `first_response_minutes`
- `priority_reason`
- `tier_snapshot`

### Entitlement Logic

Server-side function `get_support_sla_for_user(user_id)` decides SLA by effective entitlement:

1. Active `families` subscription owner -> 24h (`families_owner`)
2. Active family member under active `families` owner -> 24h (`families_member`)
3. Active `premium` subscription -> 24h (`premium`)
4. Default -> 72h (`free`)

This prevents client-side spoofing of support priority.

### Edge Functions

- `support-submit`: create ticket + first user message + email notifications
- `support-list`: return current user entitlement + recent tickets
- `support-metrics`: return aggregate response metrics (admin/moderator only)
- `admin-support`: internal support inbox actions (list/detail/reply/status/metrics)
- `admin-team`: internal team role + permission matrix management

### Metrics

Function `get_support_response_metrics(days)` returns:

- rolling average first-response time
- SLA hit rate
- responded vs total ticket counts
- per-segment breakdown (`all`, `free`, `premium`, `families_owner`, `families_member`)

## Security Model

RLS rules enforce:

- users can only read/write their own tickets/messages
- users never see internal messages
- support events are team-only
- admin/moderator can manage all support records

Role checks use the existing `has_role(auth.uid(), 'admin' | 'moderator')` helper.

## UI Integration

Support UI is available in Settings:

- create ticket form (subject, category, message)
- SLA badge for current entitlement
- recent ticket overview
- optional average-response metric card for support team users

Global support access is also available via the floating `layout.support-widget` extension.
Both the widget and admin inbox now use Supabase Realtime for live updates on
`support_tickets` and `support_messages`, with automatic polling fallback when
realtime connectivity is unavailable.

Pricing page explicitly lists support response targets for all plans.

## Operational Notes

- Do not include secrets in tickets (master password, recovery codes, private keys, vault contents)
- Email send failures do not block ticket creation
- Track SLA performance with 7d and 30d windows for internal operations
- Keep `support_tickets` and `support_messages` in `supabase_realtime` publication for live UI updates

## Internal Team Access (No-Code)

Internal support and team-rights access is now permission-based via DB-managed role mappings.

- Roles keep using `app_role` (`admin`, `moderator`, `user`)
- Effective access is derived from `role_permissions`
- Permission checks use `has_permission(user_id, permission_key)`

See `docs/ADMIN_TEAM_ACCESS.md` for the full architecture and default permission seeds.

## Required Secrets (Supabase Edge Functions)

- `RESEND_API_KEY`
- `SUPPORT_EMAIL` (optional, default: `support@mauntingstudios.de`)
- `SITE_URL` (used for deep links in emails)
