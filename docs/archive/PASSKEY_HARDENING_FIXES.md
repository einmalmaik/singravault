# Passkey Hardening Fixes (2026-02-17)

## Scope

This update hardens the passkey unlock implementation to avoid inconsistent PRF state and incorrect setup behavior.

## Changes

- Added master-password verification to `getRawKeyForPasskey` before accepting derived raw key bytes.
- Fixed `NO_PRF` handling to return a failed passkey unlock result (`success: false`).
- Added a dedicated `refreshPasskeyUnlockStatus()` action in `VaultContext` and wired it into `PasskeySettings`.
- Added passkey unlock cooldown and failed-attempt accounting via the existing rate-limiter service.
- Updated passkey PRF activation to persist both:
  - `wrapped_master_key`
  - `prf_enabled = true`
  - via a server-side WebAuthn action (`activate-prf`) after assertion verification
- Hardened registration persistence in the WebAuthn Edge Function:
  - `prf_enabled` is now only stored as `true` when a wrapped key is present.

## Database consistency

Migration added: `20260217233000_harden_passkey_prf_consistency.sql`

- Backfills legacy rows with inconsistent PRF state:
  - `prf_enabled = true` and `wrapped_master_key IS NULL` -> set `prf_enabled = false`
- Adds constraint:
  - `prf_enabled = FALSE OR wrapped_master_key IS NOT NULL`

## Challenge Binding Update (2026-04-27)

- WebAuthn challenge generation now returns a `challengeId`.
- Verification, PRF activation, and wrapped-key upgrade consume the exact challenge row instead of selecting the newest user/type challenge.
- Challenge rows are bound to the RP ID, origin, and, for credential-scoped authentication, the expected credential ID.
- Migration added: `20260427211000_bind_webauthn_challenges_to_scope.sql`.

