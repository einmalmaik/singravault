# Central 2FA and VaultFA Validation

The app does not use Supabase MFA as the primary 2FA mechanism. Singra Vault keeps its own 2FA state, but verification is server-side.

## Server-Side Validator

The shared validator is `supabase/functions/_shared/twoFactor.ts`.

It is used by:

- `auth-opaque` for account login 2FA before session issuance
- `auth-recovery` for password reset and password change 2FA before reset authorization
- `auth-2fa` for VaultFA, critical authenticated 2FA checks, and 2FA disable

The client may submit a code and context, but it does not decide whether 2FA is satisfied.

## VaultFA

VaultFA is enforced through `auth-2fa` and short-lived `two_factor_challenges`. A challenge is bound to:

- authenticated user
- purpose, for example `vault_unlock`
- expiry time
- one-time consumption

When VaultFA is active, the official app must receive a successful server verification before releasing the active Vault key. Passkeys and master passwords remain unlock methods; they do not replace VaultFA.

Limit: vault decryption remains local. Server-side VaultFA cannot retroactively protect data already decrypted on a compromised device or in a modified local client.

## Backup Codes

Backup codes are one-time-use. Current codes are stored as Argon2id `v3:` hashes. The server-side validator also supports legacy HMAC/SHA-256 formats for compatibility and consumes matching codes immediately with an `is_used = false` guard.

Backup codes cannot disable 2FA. Disabling 2FA requires a current TOTP code through `auth-2fa`.

## Rate Limits

2FA rate limits are server-side and use `rate_limit_attempts` through `_shared/authRateLimit.ts`.

Separate actions exist for:

- login TOTP and backup-code verification
- password-reset TOTP and backup-code verification
- VaultFA TOTP and backup-code verification
- 2FA disable verification
- critical 2FA verification

Failures are counted server-side by user/account and trusted client IP. The atomic DB RPC `record_auth_rate_limit_failure_atomic` is used when available, so parallel failures cannot trivially skip lockout accounting.

## Error Handling

Responses are generic. Codes, TOTP secrets, backup codes, and recovery tokens must not be logged. If status, challenge, or rate-limit state cannot be loaded, verification fails closed.
