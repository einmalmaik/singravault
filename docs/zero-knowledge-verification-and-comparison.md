# Zero-Knowledge Verification & Password-Manager Comparison

**Date:** 2026-04-24
**Scope:** Current code-backed verification of Singra Vault's vault-data zero-knowledge model and authentication boundaries.

## Part 1: Singra Vault Verification

### What The Server Sees

| Data point | Stored/processed on server | Plaintext? |
|---|---|---|
| App-login password | No | No |
| OPAQUE protocol messages | Yes, during signup/login/reset | Public protocol messages, not password-equivalent values |
| OPAQUE registration record | Yes, `user_opaque_records.registration_record` | No app password or app-password hash |
| Vault master password / vault key | No | No |
| Vault items (`encrypted_data`) | Yes | No, AES-256-GCM ciphertext |
| Encryption salt | Yes | Public salt, not useful without the master password |
| Master-password verifier | Yes | Encrypted verifier value, not an auth password hash |
| TOTP secrets | Yes | Server-side encrypted; needed for server-side 2FA verification |
| File attachments | Yes | Client-side encrypted content |

### Edge Function Review

Relevant auth functions after the OPAQUE cutover:

- `auth-opaque`: OPAQUE login and authenticated OPAQUE record registration; creates a Supabase session only after successful OPAQUE finish.
- `auth-register`: OPAQUE-only signup start/finish; receives no app password.
- `auth-reset-password`: OPAQUE-only password reset start/finish; receives no new app password.
- `auth-session`: session hydration/logout and OAuth sync only; direct password POSTs are blocked with `LEGACY_PASSWORD_LOGIN_DISABLED`.
- `auth-recovery`: recovery-code delivery/verification; the new password is enrolled later through OPAQUE.

None of these functions reads, writes, or decrypts vault item `encrypted_data`.

### Password-Leak Check

- App-owned password login sends only OPAQUE messages to Edge Functions.
- Signup and password reset perform OPAQUE registration client-side; the server stores the resulting OPAQUE record.
- There is no `auth-session` password verification path, no Argon2id server hash for app-password login, and no allowed fallback to Supabase `signInWithPassword`.
- GoTrue password verifiers are removed by migration/RPC so direct Supabase password grants cannot bypass OPAQUE.

### Admin Access

With database/service-role access an admin can read ciphertext, salts, OPAQUE records, and structural metadata, but cannot derive the app login password or vault decryption key from the current login path. Vault decryption still depends on client-side key derivation from the vault/master password.

### Important Limitation: 2FA Secrets

TOTP secrets for 2FA are server-side encrypted and decrypted server-side for verification. An attacker with both database access and the TOTP encryption key could verify or recover TOTP secrets. This does not decrypt vault data, but it is intentionally outside the vault-data zero-knowledge boundary.

## Part 2: Industry Comparison

| Feature | Singra Vault | Bitwarden | 1Password | Proton Pass |
|---|---|---|---|---|
| Vault encryption | AES-256-GCM | AES-256-CBC | AES-256-GCM | AES-256-GCM |
| Vault KDF | Argon2id | Argon2id or PBKDF2 | Argon2id | bcrypt + HKDF |
| Password leaves client for app login | No, OPAQUE | No, KDF-derived auth material | No, SRP + Secret Key model | No, per public docs |
| Open source | Source available | Client + server | Client apps partly/proprietary server | Client apps |
| Post-quantum protection for sharing keys | ML-KEM-768 + RSA-4096 wrapping paths | Not generally documented | Not generally documented | Not generally documented |
| Vault integrity checks | Client-side integrity baseline | Not equivalent | Not equivalent | Not equivalent |

This comparison is high-level and should be rechecked before publication because vendor documentation and pricing/features change.

## Remaining Gaps

- Singra Vault still needs an independent external security audit.
- The web delivery model remains sensitive to compromised shipped JavaScript, XSS, malicious extensions, or device malware.
- Existing accounts without an OPAQUE record cannot be safely auto-migrated without the password entering the server. They must use the OPAQUE reset flow.
- Metadata such as user IDs, timestamps, ownership links, and some product-level names remains structural plaintext.

## Conclusion

The public claim is technically aligned with the current implementation for app-owned password login: the app password is handled locally by OPAQUE and does not leave the client. OAuth/social login is separate, and vault unlock/master-password handling is separate. Legacy password login is not an allowed compatibility path.

**References:**

- [RFC 9807: The OPAQUE Asymmetric PAKE Protocol](https://www.rfc-editor.org/rfc/rfc9807.html)
- [Serenity OPAQUE documentation](https://opaque-auth.com/docs/)
- [Bitwarden KDF Algorithms](https://bitwarden.com/help/kdf-algorithms/)
- [Bitwarden Zero-Knowledge Encryption White Paper](https://bitwarden.com/resources/zero-knowledge-encryption-white-paper/)
