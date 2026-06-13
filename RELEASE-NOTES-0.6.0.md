# Singra Vault 0.6.0 — DIS Crypto Cutover

**Release date:** 2026-06-13
**PR:** #59 — `devin/1780326689-phase3-vault-dis-cutover` → `main`

This is a **major security-architecture release**. All in-tree cryptographic
primitives have been moved to the audited `@msdis/shield` package ("Powered by
DIS — Defensive Integration Shield"). **No user data migration is required** —
wire formats are byte-identical to 0.5.x.

---

## Security

- **Phase 6: Full crypto extraction.** Every remaining cryptographic
  primitive (Argon2id, AES-256-GCM, HKDF, HMAC, SHA-256/SHA-1, ECDSA P-256
  signing, TOTP, ML-KEM-768 hybrid wrapping, CSPRNG, UUIDs) is now consumed
  exclusively from `@msdis/shield`. No application file outside tests touches
  WebCrypto, hash-wasm or otpauth anymore.
- **ESLint guardrail fail-closed.** Direct imports of `hash-wasm`, `otpauth`
  and `@noble/post-quantum` in `src/**` are now lint-errors. Direct calls of
  `crypto.subtle`, `crypto.getRandomValues` and `crypto.randomUUID` in
  production code are blocked too. New code cannot reintroduce in-tree
  crypto without tripping the guardrail.
- **Cross-version compatibility harness.** HKDF, AES-GCM, SHA, HMAC and
  Argon2id outputs are bit-identical to the previous raw WebCrypto/hash-wasm
  paths. TOTP codes match raw `otpauth` across SHA1/SHA256/SHA512 and 6/8
  digits. All legacy backup-code hash formats still verify.
- **`@msdis/shield` resolved from the npm registry** (`^0.2.0`). Build
  and start now fail without it — Rollup cannot resolve
  `@msdis/shield/vault-crypto`.

---

## Changed

- `cryptoService.ts` — 1746 lines removed. Now a thin re-export adapter over
  `@msdis/shield/vault-crypto`. Public surface (51 names, incl. `VaultItemData`)
  preserved exactly — all importers unchanged.
- `pqCryptoService.ts` — 755 lines removed. Now a thin re-export adapter over
  `@msdis/shield/post-quantum`. Public surface (14 names) preserved exactly.
- `deviceKeyService` — Argon2id transfer wrapping, HKDF device-key
  strengthening, AES-GCM transfer envelopes, legacy HKDF wrap path all
  delegated to `@msdis/shield`.
- `twoFactorService` / `totpService` — TOTP via `@msdis/shield/totp` (incl. the
  new flexible `generateTotpCode` for imported authenticator entries). Backup
  codes via `argon2idRaw` + `hmacSha256` / `sha256Hex`.
- `passkeyService` — PRF HKDF wrap via `@msdis/shield/kdf`.
- `opaqueService` — HMAC session binding via `@msdis/shield/integrity`.
- `localSecretStore`, `desktopOAuth` (PKCE), `passwordGenerator` /
  `passwordStrength` (HIBP SHA-1), `secureBuffer`, `vaultIntegrityV2`
  canonical hash, UI-layer UUIDs — all consume `@msdis/shield` only.
- **OpLog** — ECDSA P-256 device signing via `@msdis/shield/signing`. Record &
  snapshot HKDF + AES-GCM via `@msdis/shield/kdf` / `aead`. All SHA-256 hashes
  via `@msdis/shield/integrity`. UUIDs/nonces via `@msdis/shield/random`.
- **CI** — security workflow now checks out full git history so `gitleaks`
  can diff the PR range. OSV scanner job fixed and unblocked.

---

## Stats

43 files changed, +436 / −3078 lines. Net **−2642 lines of crypto code**
removed from the application and moved to the audited `@msdis/shield` package.

| File | Before | After |
|------|-------:|------:|
| `src/services/cryptoService.ts`    | 1746 lines removed | thin re-export |
| `src/services/pqCryptoService.ts`  |  755 lines removed | thin re-export |
| `src/services/deviceKeyService.ts` |  139 lines removed | uses `@msdis/shield/{kdf,aead,random}` |
| `src/services/twoFactorService.ts` |   91 lines removed | uses `@msdis/shield/{totp,kdf,integrity,random}` |
| `src/services/vaultOpLog/operationSigningService.ts` | 74 lines removed | uses `@msdis/shield/signing` |
| `src/services/vaultOpLog/snapshotCrypto.ts` |  70 lines removed | uses `@msdis/shield/{kdf,aead,integrity,random}` |
| `src/services/vaultOpLog/cryptoRecordService.ts` | 62 lines removed | uses `@msdis/shield/{kdf,aead,random}` |
| `src/services/collectionOpLog/crypto.ts` | 49 lines removed | uses `@msdis/shield/{kdf,aead,random}` |
| `src/services/passkeyService.ts`    |  45 lines removed | uses `@msdis/shield/{kdf,aead,random}` |
| `src/services/totpService.ts`       |  37 lines removed | uses `@msdis/shield/totp` |

---

## Migration

**No action required.** All wire formats are byte-identical to 0.5.x. Existing
vaults unlock unchanged. No data migration, no re-enrollment, no
re-onboarding, no key rotation.

---

## CI status (target)

- `npm run lint` — 0 errors
- `npx tsc --noEmit` — green
- `npm run test` — full Vault suite green
- `npm run build` — green
- `npm run build:core-only` — green
- `tauri build` — green (Windows MSI / Linux deb+AppImage / macOS dmg)
- Vercel preview deploy — green

---

## Install notes for downstream

`@msdis/shield` is consumed from the **public npm registry**. `npm install`
resolves the latest matching `^0.2.0`. No GitHub token required.
