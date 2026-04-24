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
5. `auth-opaque` `login-finish` verifies the OPAQUE proof, enforces 2FA if needed, and creates the Supabase session.
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

### Password Reset

Password reset re-enrolls OPAQUE credentials:

1. `auth-recovery` verifies the recovery code and returns a reset token.
2. The client starts OPAQUE registration for the new password.
3. `auth-reset-password` `opaque-reset-start` returns a registration response.
4. The client finishes OPAQUE registration locally.
5. `auth-reset-password` `opaque-reset-finish` stores the new OPAQUE record, removes GoTrue password verifiers, revokes sessions, and clears reset state.

The new app password is never sent to the server.

### OAuth/Social Login

OAuth providers (`google`, `discord`, `github`) use `supabase.auth.signInWithOAuth()`. After the OAuth callback, `auth-session` `oauth-sync` can establish the BFF cookie/session. OAuth is not treated as an OPAQUE login and must not fall into app-password logic.

## Vault Unlock

`VaultUnlock` is separate from app authentication. It unlocks local vault encryption after an app session exists. The master password/vault key path is not a replacement for OPAQUE login and is not sent to auth Edge Functions.

## Master Password Setup

`MasterPasswordSetup` configures vault encryption material. It uses local KDF and encrypted verifier logic for vault unlock, not app login.

## 2FA

2FA for app-password login is enforced inside `auth-opaque` after successful OPAQUE verification and before session issuance. Backup-code verification still uses Argon2id hashes, but those hashes are backup-code material, not app-password hashes.
