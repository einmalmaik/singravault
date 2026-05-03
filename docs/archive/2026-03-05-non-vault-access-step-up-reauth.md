# Non-Vault Access and Step-Up Reauth (2026-03-05)

## Scope

This update separates account-level access from vault-unlock state and adds
step-up reauthentication for destructive account actions.

## Unlock Policy

- `ProtectedRoute` still enforces authentication.
- A new route contract field `requiresVaultUnlock?: boolean` controls whether a
  route additionally requires vault unlock.
- Vault-only routes (`/vault-health`, `/authenticator`, `/vault/emergency/:id`)
  must set `requiresVaultUnlock: true`.
- Non-vault routes (for example settings/account/subscription/admin) stay
  accessible while the vault is locked.

## Settings Behavior

- `/settings` no longer hard-redirects to `/vault` when the vault is locked.
- A lock notice explains that account/billing settings remain available.
- Vault-dependent sections stay guarded and show explicit locked-state messages.

## Step-Up Reauth (5-Minute Rule)

- New client service: `src/services/sensitiveActionReauthService.ts`
  - `isSensitiveActionSessionFresh(maxAgeSeconds = 300)`
  - `reauthenticateWithAccountPassword(password)`
  - `getSensitiveActionReauthMethod()`
  - `reauthenticateWithSessionRefresh()`
- New dialog: `src/components/security/SensitiveActionReauthDialog.tsx`
- Sensitive actions requiring fresh session:
  - `delete_my_account` (core RPC)
  - `cancel-subscription` (premium edge function)
- Reauth UX by account type:
  - Password-capable accounts: confirm account password
  - Social-only accounts: explicit keyword confirmation + token refresh fallback

## Server Enforcement

- Core migration: `supabase/migrations/20260305163206_require_fresh_session_for_delete_account.sql`
  - `delete_my_account()` rejects stale JWTs (`iat` older than 300 seconds) with `REAUTH_REQUIRED`.
- Premium edge function `cancel-subscription` enforces the same JWT `iat`
  freshness window and returns `403` + `REAUTH_REQUIRED`.

## Client Error Contract

- Subscription cancel flow now handles `REAUTH_REQUIRED` explicitly and opens
  the reauth dialog.
- Account deletion flow also handles server-side `REAUTH_REQUIRED` defensively.
