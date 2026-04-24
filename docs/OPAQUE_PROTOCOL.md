# OPAQUE Protocol Integration

**Stand:** 2026-04-24

Singra Vault uses OPAQUE for every app-owned password login. OAuth/social login is a separate authentication path; vault unlock/master-password handling is also separate. A password login that is not OAuth/social must go through OPAQUE.

The implementation uses `@serenity-kit/opaque` (RFC 9807 based). The app password is processed only in the client. Edge Functions receive OPAQUE protocol messages (`registrationRequest`, `registrationRecord`, `startLoginRequest`, `finishLoginRequest`), never the app password, a password hash, or a password-equivalent derived from the app password.

## Current Auth Paths

| Path | Product meaning | Productively reachable | Password handling |
|---|---|---:|---|
| OPAQUE login | App-owned email/password login | Yes | Password stays on client |
| OAuth/social login | Google/Discord/GitHub via Supabase OAuth | Yes | Not an OPAQUE path |
| Vault unlock | Master password / vault key derivation | Yes, after app session | Local vault KDF only |
| Passkeys / 2FA / account actions | Add-on auth/account flows | Yes, separate | Not a legacy password login |
| Legacy password login | Old `auth-session`/GoTrue password path | No | Server-side blocked |

## Files

| File | Purpose |
|---|---|
| `src/pages/Auth.tsx` | Login, signup, reset and OAuth UI orchestration |
| `src/services/opaqueService.ts` | Client-side OPAQUE wrapper, identifier normalization, server-key pinning, session binding verification |
| `src/services/accountPasswordResetService.ts` | Shared client reset/change state transitions; never sends the new account password |
| `supabase/functions/auth-opaque/index.ts` | Server-side OPAQUE login and authenticated OPAQUE record registration |
| `supabase/functions/auth-register/index.ts` | OPAQUE-only signup start/finish |
| `supabase/functions/auth-recovery/index.ts` | Shared email-code and 2FA authorization for forgot-password and authenticated password-change |
| `supabase/functions/auth-reset-password/index.ts` | OPAQUE-only password reset start/finish |
| `supabase/functions/auth-session/index.ts` | Session hydration/logout and OAuth sync only; password POSTs return `LEGACY_PASSWORD_LOGIN_DISABLED` |
| `supabase/functions/_shared/opaqueAuth.ts` | Shared identifier normalization and session-binding proof helpers |
| `supabase/migrations/20260424120000_enforce_opaque_password_auth.sql` | OPAQUE identifiers, one-time states, and GoTrue password-grant hard block |
| `supabase/migrations/20260424193000_opaque_password_reset_change_flow.sql` | Reset/change authorization fields, reset rate limits, and DB trigger blocking GoTrue password verifier writes |

## Login Flow

```text
Client                                      Server
  normalizeOpaqueIdentifier(email)
  startLogin(password)
  -> login-start: identifier + startLoginRequest
                                             load OPAQUE record by normalized identifier
                                             createLoginResponse()
  <- loginResponse + loginId
  finishLogin(password, loginResponse)
  verify pinned serverStaticPublicKey
  -> login-finish: identifier + loginId + finishLoginRequest (+ optional 2FA)
                                             finishLogin()
                                             optional TOTP / backup-code check
                                             create Supabase session
                                             HMAC-bind session to OPAQUE sessionKey
  <- session + opaqueSessionBinding
  verify session binding before applying session
```

If any OPAQUE step fails, login stops. There is no automatic or manual fallback to a password-over-TLS flow.

## Registration, Reset, And Password Change

Signup, forgot-password, and authenticated password-change are OPAQUE registrations:

1. The client checks password quality locally and starts OPAQUE registration.
2. The server returns a registration challenge/response and stores only short-lived server state.
3. The client finishes OPAQUE registration locally and sends the `registrationRecord`.
4. The server stores the record in `user_opaque_records` using the normalized identifier.
5. The server removes GoTrue password verifiers via `disable_gotrue_password_login()` so direct Supabase password grants cannot bypass OPAQUE.

Forgot-password and authenticated password-change share the same authorization sequence:

```text
START
  -> request email code (anti-enumeration for forgot-password)
  -> verify one-time email code
  -> TWO_FACTOR_REQUIRED when account 2FA is enabled
  -> verify TOTP or recovery code
  -> NEW_PASSWORD_ALLOWED
  -> OPAQUE re-registration
  -> revoke existing sessions
  -> DONE
```

`auth-reset-password` refuses OPAQUE re-registration until the reset challenge has `authorized_at`; when 2FA was enabled it also requires `two_factor_verified_at`. The new account password is not sent to `auth-recovery`, `auth-reset-password`, Supabase Auth, or logs. The authenticated settings flow signs the local client out after success because the server revokes refresh tokens/sessions.

Existing accounts without an OPAQUE record cannot be migrated server-side because the server must not know the app password. They must use the OPAQUE reset flow to enroll a new OPAQUE registration record. This is a compatibility path, not a legacy login path.

## Identifier Binding

All app-owned password flows use `normalizeOpaqueIdentifier(email)`:

```text
trim(email).toLowerCase()
```

The normalized identifier is used for signup, reset, `login-start`, `login-finish`, and one-time server login state. OAuth/social-only accounts do not need an OPAQUE identifier until the product explicitly adds an app-owned password to that account.

## Server Static Public Key Pinning

`@serenity-kit/opaque` returns `serverStaticPublicKey` from `finishRegistration()` and `finishLogin()`. The client validates it against:

```text
VITE_OPAQUE_SERVER_STATIC_PUBLIC_KEY
```

If the pin is missing or the key mismatches, the client fails closed and does not create/apply a session. The expected pin is derived from the long-lived `OPAQUE_SERVER_SETUP` using the library's documented helper, for example:

```text
npx @serenity-kit/opaque@latest get-server-public-key "<server setup string>"
```

## Session Binding

OPAQUE produces a shared `sessionKey` on client and server. The server creates the Supabase session only after a successful OPAQUE finish, then returns:

```text
HMAC-SHA256(sessionKey, "opaque-session-binding-v1\n<user-id>\n<access-token>")
```

The client verifies this binding before applying the Supabase session. OAuth sessions are not described as OPAQUE sessions and use the separate `oauth-sync` path.

## Legacy Blocking

Legacy password login is blocked at multiple layers:

- `Auth.tsx` has no `legacyLogin()` and no `migrateToOpaque()` fallback.
- OPAQUE errors throw and abort login.
- `auth-session` accepts only session hydration/logout/OAuth sync; password POSTs return HTTP `410` with `LEGACY_PASSWORD_LOGIN_DISABLED`.
- `auth-session` contains no `signInWithPassword` and no app-password Argon2 verification.
- Signup/reset store OPAQUE records and remove `user_security` rows.
- The migration nulls `auth.users.encrypted_password` and adds `disable_gotrue_password_login()` for future OPAQUE registration/reset writes.
- `enforce_opaque_no_gotrue_password_on_auth_users` clears direct GoTrue password verifier writes, including direct `supabase.auth.updateUser({ password })` attempts.

## Key Stretching

The client sets Serenity's `keyStretching` explicitly to `memory-constrained`. This preserves compatibility with existing OPAQUE records that were created under the previous library default. Raising it would require a deliberate OPAQUE record rotation plan.
