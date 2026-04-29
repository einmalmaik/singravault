# Admin Permission Audit (2026-03-08)

## Findings

- The admin button and `/admin` access depend on `admin-team` edge-function calls.
- Live Supabase edge logs showed repeated `401` responses for `admin-team`, which explains the missing admin button despite a valid admin role.
- The live database currently contains exactly one `admin` role assignment in `public.user_roles`.
- The same admin account currently has an active `premium` subscription, not an active `families` subscription.
- Before this fix, admin-only feature bypassing was inconsistent:
  - admin access was resolved through `getTeamAccess()`
  - feature gates were resolved only through subscription tier
  - therefore an admin could still lose families-only capabilities while still being treated as admin elsewhere

## Fix

- Added a core-local `adminService` that routes admin edge-function calls through the shared authenticated invocation helper.
- Overrode the premium registry's `/admin` route and `getTeamAccess` service hook so the app uses the repaired admin path without waiting for a premium package release.
- Added an admin feature override in `SubscriptionContext` so admins keep premium/families feature access consistently, even when their stored paid tier is lower than the internal admin role.

## Verified

- Supabase database state for `user_roles`, `role_permissions`, `subscriptions`, and relevant helper functions.
- Live edge-function logs for repeated `admin-team` `401` responses.
- Targeted unit/context tests for the local admin service and admin feature override.
