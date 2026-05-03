# Auth Components — Authentication & Vault Setup

> **Files:**
> `src/pages/Auth.tsx`  
> `src/components/vault/VaultUnlock.tsx`  
> `src/components/vault/MasterPasswordSetup.tsx`  
> `src/components/auth/TwoFactorVerificationModal.tsx`

## Auth Page

`src/pages/Auth.tsx` owns user-facing login, signup, recovery, password reset, and OAuth entry points.

### App-Owned Password Login

The app-password path uses OPAQUE only:

1. Normalize the identifier with `normalizeOpaqueIdentifier(email)`.
2. `opaqueService.startLogin(password)` creates a blinded OPAQUE request locally.
3. `auth-opaque` `login-start` returns `loginResponse` and `loginId`.
4. `opaqueService.finishLogin(...)` derives the OPAQUE `sessionKey` locally and validates the pinned server static public key.
5. `auth-opaque` `login-finish` verifies the OPAQUE proof, enforces 2FA through the shared server-side 2FA validator if needed, and creates the Supabase session.
6. The client verifies `opaqueSessionBinding` before applying the session.

Failure in any OPAQUE step aborts login. There is no legacy password fallback.

### Signup

Signup is OPAQUE registration:

1. Password quality is checked locally.
2. The client starts OPAQUE registration and sends only `registrationRequest`.
3. `auth-register` returns `registrationResponse` and a short-lived registration id.
4. The client finishes OPAQUE registration and sends `registrationRecord`.
5. The server stores the OPAQUE record and removes GoTrue password verifiers.
6. The user verifies the signup OTP, then logs in through OPAQUE.

The app password is not sent to `auth-register`.

### Password Reset And Password Change

Forgot-password and authenticated password-change use the same reset authorization and OPAQUE re-enrollment logic:

1. `accountPasswordResetService` requests an email code through `auth-recovery`.
2. `auth-recovery` verifies the one-time email code without issuing an app session.
3. If account 2FA is enabled, `auth-recovery` requires a TOTP code or recovery code through the shared server-side 2FA validator before authorizing the reset token.
4. The client starts OPAQUE registration for the new password.
5. `auth-reset-password` `opaque-reset-start` returns a registration response only for an authorized reset token.
6. The client finishes OPAQUE registration locally.
7. `auth-reset-password` `opaque-reset-finish` calls `finish_opaque_password_reset(...)`, which atomically stores the new OPAQUE record, removes GoTrue password verifiers, revokes sessions, and clears reset state.

The new app password is never sent to the server. Email reset codes are stored as versioned HMAC-SHA-256 values bound to purpose, normalized email, and code via `AUTH_RECOVERY_CODE_PEPPER`; short-lived legacy SHA-256 records are accepted only until their normal expiry.

Authenticated password-change does not let the user edit the email address; the server reads it from the current session. OAuth/social-only accounts do not enter this app-password flow.

Direct Supabase recovery/signup/magiclink/email-change callbacks are not accepted as app sessions. The Supabase client has `detectSessionInUrl: false`; `Auth.tsx` only applies expected OAuth callbacks and routes account recovery through `auth-recovery` plus `auth-reset-password`.

### OAuth/Social Login

OAuth providers (`google`, `discord`, `github`) use `supabase.auth.signInWithOAuth()`. After the OAuth callback, `auth-session` `oauth-sync` can establish the BFF cookie/session. OAuth is not treated as an OPAQUE login and must not fall into app-password logic.

## Vault Unlock

`VaultUnlock` is separate from app authentication. It unlocks local vault encryption after an app session exists. The master password/vault key path is not a replacement for OPAQUE login and is not sent to auth Edge Functions.

Resetting the account password does not decrypt the vault and does not recreate a lost vault key. Existing access JWTs can remain valid until the configured Supabase JWT TTL (`supabase/config.toml`: 600 seconds); refresh tokens and sessions are revoked during OPAQUE reset finish.

## Master Password Setup

`MasterPasswordSetup` configures vault encryption material. It uses local KDF and encrypted verifier logic for vault unlock, not app login.

## 2FA

2FA for app-password login is enforced inside `auth-opaque` after successful OPAQUE verification and before session issuance. 2FA for password reset/change is enforced inside `auth-recovery` before the reset token can be used for OPAQUE re-registration.

The server-side implementation is centralized in `supabase/functions/_shared/twoFactor.ts`. It owns TOTP verification, backup-code verification/consumption, purpose-specific rate-limit actions, and generic error handling. Backup-code verification supports current Argon2id `v3:` hashes plus legacy HMAC/SHA-256 formats for compatibility; backup codes are consumed server-side with an `is_used = false` guard.

Vault 2FA/VaultFA uses `auth-2fa`. The client may request a requirement or submit a code, but the server creates and consumes short-lived `two_factor_challenges` bound to the authenticated user and purpose. If VaultFA is enabled and the server cannot verify the code, the official app keeps the Vault locked and does not release the Vault key.

2FA disable is also handled by `auth-2fa` and accepts only the current TOTP code. Backup codes are rejected for `disable_2fa`.

Limit: Vault decryption remains local. Server-side VaultFA prevents the official client from releasing the Vault key before server verification, but it cannot retroactively protect data already decrypted on a compromised device or in a modified local client.
