# Supabase JWT/RPC Hardening (2026-02-19)

## Scope
- Enforce `verify_jwt = true` for all user-facing Edge Functions.
- Keep `stripe-webhook` on `verify_jwt = false` (Stripe signature validation endpoint).
- Harden `SECURITY DEFINER` RPC functions against cross-user oracle access.
- Remove broad `PUBLIC`/`anon` execute grants for sensitive RPC functions.

## Changes
- Updated `supabase/config.toml`:
  - Set `verify_jwt = true` for:
    - `accept-family-invitation`
    - `admin-support`
    - `admin-team`
    - `cancel-subscription`
    - `create-checkout-session`
    - `create-portal-session`
    - `invite-emergency-access`
    - `invite-family-member`
    - `rate-limit`
    - `send-test-mail`
    - `support-list`
    - `support-metrics`
    - `support-submit`
    - `webauthn`
  - Kept `stripe-webhook` with `verify_jwt = false`.

- Added migration:
  - `supabase/migrations/20260219183000_harden_security_definer_rpc_access.sql`
  - Hardened functions:
    - `has_role`
    - `has_permission`
    - `is_shared_collection_member`
    - `user_has_active_paid_subscription`
    - `get_support_sla_for_user`
  - Access model:
    - Authenticated users can only query their own identity data (`auth.uid()` bound).
    - `service_role` remains allowed for trusted backend flows.
  - Privilege hardening:
    - `REVOKE EXECUTE ... FROM PUBLIC, anon`
    - Explicit `GRANT EXECUTE ... TO authenticated, service_role`

## Security Impact
- Reduces risk of role/subscription/membership enumeration by arbitrary user UUID.
- Aligns Edge Function gatekeeping with platform-level JWT enforcement.
- Preserves existing admin/backend workflows that require `service_role`.
