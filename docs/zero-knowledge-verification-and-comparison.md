# Zero-Knowledge Verification & Password-Manager Comparison

**Date:** 2026-04-26
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
| Vault item title/type/favorite/category columns | Yes | Neutral placeholders for new writes; legacy rows may remain until client migration |
| Encryption salt | Yes | Public salt, not useful without the master password |
| Master-password verifier | Yes | Encrypted verifier value, not an auth password hash |
| TOTP secrets | Yes | Server-side encrypted; needed for server-side 2FA verification |
| File attachments | Yes | Client-side encrypted chunks plus encrypted manifest; server sees only opaque paths, ciphertext, owner binding, timestamps, chunk/object counts, and ciphertext sizes |

### Edge Function Review

Relevant auth functions after the OPAQUE cutover:

- `auth-opaque`: OPAQUE login and authenticated OPAQUE record registration; creates a Supabase session only after successful OPAQUE finish.
- `auth-register`: OPAQUE-only signup start/finish; receives no app password.
- `auth-reset-password`: OPAQUE-only password reset/change start/finish; receives no new app password and refuses tokens that have not passed email-code plus required 2FA authorization.
- `auth-session`: session hydration/logout and OAuth sync only; direct password POSTs are blocked with `LEGACY_PASSWORD_LOGIN_DISABLED`.
- `auth-recovery`: shared forgot-password/password-change email-code delivery and verification, plus required TOTP/recovery-code verification; the new password is enrolled later through OPAQUE.

None of these functions reads, writes, or decrypts vault item `encrypted_data`.

### Password-Leak Check

- App-owned password login sends only OPAQUE messages to Edge Functions.
- Signup, password reset, and password change perform OPAQUE registration client-side; the server stores the resulting OPAQUE record.
- There is no `auth-session` password verification path, no Argon2id server hash for app-password login, and no allowed fallback to Supabase `signInWithPassword`.
- GoTrue password verifiers are removed by migration/RPC and direct verifier writes are cleared by a database trigger so direct Supabase password grants or `updateUser({ password })` cannot bypass OPAQUE.

### Admin Access

With database/service-role access an admin can read ciphertext, salts, OPAQUE records, and structural metadata, but cannot derive the app login password or vault decryption key from the current login path. Vault decryption still depends on client-side key derivation from the vault/master password.

New vault item writes are forced through neutral server-visible metadata placeholders by migration `20260427210000_enforce_opaque_vault_item_metadata.sql`. Existing legacy rows are not bulk-wiped by that migration because SQL cannot safely copy remaining plaintext metadata into encrypted payloads.

### Platform Boundary

Web/PWA local secret storage uses IndexedDB plus a non-extractable browser `CryptoKey` when available. This is a browser defense-in-depth layer, not an OS secret boundary. Tauri/Desktop local secrets use the OS keychain through narrowly scoped Rust commands, which is the stronger local Device-Key storage path.

### Recovery And Emergency Access

Recovery and Emergency Access create separate key-access workflows. They are encrypted client-side, but they still expand the trusted computing base and must be treated as alternative Vault-key paths with their own revocation, notification, waiting-period and trustee-account risks.

### Premium File Attachments

Premium file attachments use a chunked E2EE format (`sv-file-manifest-v1`). The client generates a random AES-256-GCM file key per file, wraps that file key with the locally unlocked vault/UserKey, encrypts every file chunk locally with its own nonce and AAD, and uploads only ciphertext chunks to the private `vault-attachments` bucket. The manifest is also encrypted and authenticated client-side; it contains the original filename, extension, MIME type, original size, last-modified time, chunk list, ciphertext hashes, revision data, and preview metadata.

The server does not need the original filename, MIME type, extension, EXIF/PDF/text metadata, thumbnails, previews, or plaintext content. The remaining visible metadata is technical: owner/user binding, vault item binding, upload/update timestamps, opaque storage path prefix, ciphertext object sizes, chunk count, approximate storage usage, and access timing. File size is not padded yet, so object sizes reveal an approximate plaintext size.

Downloads prefer a streaming plaintext writer. In browsers with the File System Access API, decrypted chunks are written to the selected file handle one by one and then zeroed best-effort. In Tauri/Desktop, decrypted chunks are written to a temporary `.singra-partial` file and atomically renamed after success; the partial file is removed on handled errors. Browsers without a writable file API still use a documented Blob fallback, which may hold the full plaintext in memory and is not the preferred path for very large files.

Upload currently uses own encrypted chunk objects rather than Supabase TUS resumable uploads. This keeps the cryptographic unit of authentication aligned with the manifest: each object is an independently authenticated ciphertext chunk, and the attachment row becomes visible only after the encrypted manifest is committed. Supabase TUS can be evaluated later as a transport for encrypted objects, but it must not replace client-side E2EE or expose names/MIME/extensions.

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
- Browser/PWA local secret storage does not protect against compromised same-origin JavaScript, malicious extensions, or a compromised renderer.
- Emergency Access and other sharing/recovery flows are alternative key paths, not part of the narrow single-user vault-payload boundary.
- File attachment rollback protection is detection-oriented. Manifests are versioned, carry a manifest root and previous-manifest hash field, and chunks are bound through AAD to user, item, file, revision, manifest root, index, and chunk count. The client stores a local last-seen revision/hash checkpoint and blocks older/conflicting manifests when that checkpoint exists. Without a trustworthy local checkpoint or an external transparency/audit system, a fully malicious server can still replay an older valid ciphertext state to a fresh device.

## Conclusion

The public claim is technically aligned with the current implementation for app-owned password login, password reset, and password change: the app password is handled locally by OPAQUE and does not leave the client. OAuth/social login is separate, and vault unlock/master-password handling is separate. Legacy password login/reset is not an allowed compatibility path.

**References:**

- [RFC 9807: The OPAQUE Asymmetric PAKE Protocol](https://www.rfc-editor.org/rfc/rfc9807.html)
- [Serenity OPAQUE documentation](https://opaque-auth.com/docs/)
- [Bitwarden KDF Algorithms](https://bitwarden.com/help/kdf-algorithms/)
- [Bitwarden Zero-Knowledge Encryption White Paper](https://bitwarden.com/resources/zero-knowledge-encryption-white-paper/)
- [Supabase Storage resumable uploads](https://supabase.com/docs/guides/storage/uploads/resumable-uploads)
- [WHATWG Streams](https://streams.spec.whatwg.org/)
- [File System Access API](https://developer.chrome.com/docs/capabilities/web-apis/file-system-access)
- [Web Cryptography API](https://www.w3.org/TR/webcrypto-2/)
- [NIST SP 800-38D: GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [The Update Framework security model](https://theupdateframework.io/docs/security/)
