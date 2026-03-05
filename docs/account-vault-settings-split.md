# Account/Vault Settings Split

Date: 2026-03-05

## Summary

The authenticated UX was adjusted to separate account-level and vault-level actions:

- Post-login default redirect now goes to `/` (landing) when no explicit redirect target is present.
- Landing header for authenticated users now shows:
  - `Vault` button
  - `Account` dropdown (`Settings`, `Logout`)
- `/settings` now focuses on account settings (appearance, subscription, password change, 2FA, account actions).
- New route `/vault/settings` contains vault-specific settings and remains vault-unlock protected.

## Routing

- `/settings`: auth required, vault unlock not required.
- `/vault/settings`: auth required, vault unlock required.
- `/vault`: unchanged unlock flow (master password prompt when locked).

## Vault-Specific Sections

Vault settings now include:

- Vault security controls (auto-lock, lock now, passkey/device key, duress when available)
- Data import/export
- Premium vault sections (Emergency, Family, Shared Collections) when registered

## Account-Specific Additions

`/settings` now includes direct password update via `supabase.auth.updateUser`.
