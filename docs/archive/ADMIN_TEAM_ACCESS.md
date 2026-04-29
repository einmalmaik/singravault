# Internal Team Admin & No-Code Rights

## Overview

Singra Vault now includes an internal admin area for support operations and team-rights management.

Scope is intentionally **internal-team only**:

- no new end-user permission model
- no customer-facing RBAC complexity
- support and team rights are managed centrally for staff

## What Was Added

### Database (No-Code Permission Matrix)

Migration: `supabase/migrations/20260214110000_internal_team_access_matrix.sql`

New tables:

- `team_permissions` — permission catalog (key, label, description, category)
- `role_permissions` — mapping from internal roles (`admin`/`moderator`) to permission keys
- `team_access_audit_log` — audit trail for role/permission changes

New functions:

- `has_permission(user_id, permission_key)`
- `get_my_permissions()`

`get_support_response_metrics(days)` now checks `has_permission(..., 'support.metrics.read')` instead of fixed `admin/moderator` logic.

### Edge Functions

- `admin-team`
  - `get_access`
  - `list_members`
  - `set_member_role`
  - `list_role_permissions`
  - `set_role_permission`

- `admin-support`
  - `list_tickets`
  - `get_ticket`
  - `reply_ticket`
  - `update_ticket`
  - `list_metrics`

Both functions enforce access via permission keys (`has_permission`) before privileged operations.

### Frontend

Route:

- `/admin` (`src/pages/AdminPage.tsx`)

Panels:

- `src/components/admin/AdminSupportPanel.tsx`
- `src/components/admin/AdminTeamPermissionsPanel.tsx`

Service layer:

- `src/services/adminService.ts`

The admin page is guarded by effective permissions returned from `admin-team:get_access`.
The payload now also includes diagnostics:

- `has_internal_role`: whether the user has `admin` or `moderator`
- `missing_admin_permissions`: permission keys not currently assigned from the admin access set

## Default Permission Seeds

Permission keys (seeded in migration):

- `support.admin.access`
- `support.tickets.read`
- `support.tickets.reply`
- `support.tickets.reply_internal`
- `support.tickets.status`
- `support.metrics.read`
- `team.roles.read`
- `team.roles.manage`
- `team.permissions.read`
- `team.permissions.manage`

Default role mappings:

- `admin`: all permission keys
- `moderator`: support operations + read-only team visibility (no role/permission write access)

## Operational Notes

- Role and permission changes happen in-app (no code deploy required).
- All internal write operations are logged in `team_access_audit_log`.
- End-user support flow (widget/settings ticket creation) remains unchanged.
- Internal team membership views include only users with internal roles (`admin` or `moderator`).
- The end-user baseline role (`user`) is explicitly blocked from receiving internal support/team permissions.
- The `/admin` surface is hard-gated to internal team users (`admin`/`moderator`) with matching permissions.
- Frontend admin calls always send an explicit user session JWT to prevent anon-token fallback and 401 races.
- If `/admin` is denied after a refactor/migration, first check:
  - user has internal role (`admin` or `moderator`) in `user_roles`
  - at least one required admin-access permission is mapped via `role_permissions`
