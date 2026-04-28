# Metadata, Edge Function and Tauri Follow-up - 2026-04-28

Branch: `feat/zero-knowledge.hardering`  
Baseline commit: `b3a27c3` (`Harden CORS and remove leaked loadtest artifacts`)  
Scope: Metadata zero-knowledge proof for new Vault writes, legacy metadata migration strategy, `verify_jwt = false` Edge Function classification, Tauri desktop boundary and Web/PWA storage/cache boundary.

## Repository State

- `b3a27c3` is contained in the current branch and was `HEAD` before this follow-up work.
- No commits existed after `b3a27c3` at the start of this pass.
- The working tree was clean at the start of this pass.
- Open PRs remained #45, #46 and #47, all security-related older branches.
- `gh run list --limit 20` showed green `ci` on `main`; no newer branch CI run for `b3a27c3` appeared in the first 20 results.
- `gh issue list --state open --limit 20` returned no open issues.

## Metadata Proof

New Vault writes must only expose technical row metadata and ciphertext. Sensitive item semantics belong in `vault_items.encrypted_data`, encrypted client-side and AAD-bound to the item id.

| Data point | Client source | Server-visible location | Sensitivity | Current status | Target status | Proof / Test |
| --- | --- | --- | --- | --- | --- | --- |
| Item title | `VaultItemDialog` form | `vault_items.title` | Sensitive | Neutralized to `Encrypted Item` for new writes | Neutralized server-side | `vaultMetadataPolicy.test.ts`, `security-hardening-contracts.test.ts`, DB trigger |
| Website URL | `VaultItemDialog` form | `vault_items.website_url` | Sensitive | `null` for new writes; legacy fallback read remains | Encrypted in payload; legacy fallback only | `vaultMetadataPolicy.test.ts`, `offlineVaultService.test.ts`, SQL verification |
| Username / login email | `VaultItemDialog` form | No dedicated server column | Sensitive | Encrypted in payload | Encrypted in payload | `vaultItemCryptoStorage.test.ts` |
| Notes | `VaultItemDialog` form | No dedicated server column | Sensitive | Encrypted in payload | Encrypted in payload | `vaultItemCryptoStorage.test.ts` |
| Password | `VaultItemDialog` form | No dedicated server column | Sensitive | Encrypted in payload | Encrypted in payload | `vaultItemCryptoStorage.test.ts` |
| TOTP item secret | `VaultItemDialog` form | No vault server column; account 2FA uses separate `user_2fa` path | Sensitive | Vault TOTP encrypted in payload; account 2FA outside Vault ZK | Encrypted in payload for Vault items | `vaultItemCryptoStorage.test.ts` |
| TOTP issuer/label/algorithm | `VaultItemDialog` form | No dedicated vault server column | Sensitive metadata | Encrypted in payload | Encrypted in payload | `vaultItemCryptoStorage.test.ts` |
| Item type | `VaultItemDialog` form | `vault_items.item_type` | Sensitive metadata | Neutralized to `password` compatibility placeholder for new writes | Neutralized server-side | `vaultMetadataPolicy.test.ts`, DB trigger |
| Favorite state | `VaultItemDialog` form | `vault_items.is_favorite` | Sensitive intent metadata | Neutralized to `false` for new writes | Encrypted or neutralized | `vaultMetadataPolicy.test.ts`, DB trigger |
| Category assignment | `VaultItemDialog` form | `vault_items.category_id` | Sensitive relationship metadata | Neutralized to `null`; encrypted payload carries assignment | Encrypted payload, no server relation | `CategoryDialog` unlink path, `vaultMetadataPolicy.test.ts` |
| Category name/icon/color | `CategoryDialog` form | `categories.name/icon/color` | Sensitive metadata | Stored as `enc:cat:v1:*`; trigger rejects plaintext | Encrypted category envelope | `security-hardening-contracts.test.ts`, SQL verification |
| Category parent/sort | `CategoryDialog` form | `categories.parent_id/sort_order` | Sensitive relationship/order metadata | Neutralized to `null` | Neutralized | DB trigger, SQL verification |
| Tags/search tokens | Not present as dedicated write path in reviewed core code | No dedicated exposed table found | Sensitive | Not applicable in current core | Must be encrypted if added | Follow-up invariant |
| Attachment filename/MIME/extension/preview/manifest semantics | Premium attachment flow / pending hooks | Storage object path and payload | Sensitive | Core docs classify as E2EE; object size/timing remain visible | No semantic object names or plaintext previews | Follow-up review item for premium attachment implementation |
| `user_id`, `vault_id`, `item_id` | Auth/session/row identity | `vault_items`, `categories`, storage paths | Technical metadata | Server-visible | Outside Vault ZK boundary | RLS and ownership checks |
| `created_at`, `updated_at`, revision | DB/sync | Rows and sync head | Technical/sync metadata | Server-visible | Minimized technical metadata | Sync-head tests |
| Ciphertext size and access timing | Encryption/storage/runtime | DB/storage/network | Side-channel metadata | Server-visible | Residual risk | Documented limitation |

## Legacy Migration

Safe migration strategy:

- Detect legacy item rows when server-visible metadata is not neutral: `title <> 'Encrypted Item'`, non-null URL/category/icon/sort/last-used, non-placeholder `item_type`, or `is_favorite = true`.
- On unlock, decrypt `encrypted_data`. If payload lacks fields that only exist in legacy columns, merge legacy metadata into the decrypted payload locally.
- Re-encrypt with the current `sv-vault-v1:` AAD-bound envelope using the item id as AAD.
- Upsert only `encrypted_data` plus neutralized compatibility fields.
- Repeat idempotently; interruption is safe because original legacy fields remain until the item has a readable encrypted payload and has been rewritten.
- Only after telemetry/tests show no legacy rows remain should fallback reads and legacy columns be removed in a separate migration.

Implemented in this pass:

- Added `vaultMetadataPolicy.ts` as the central policy for server-visible item metadata.
- Routed new item writes, category unlink rewrites, offline queued item upserts and quarantine trusted-snapshot restore through `neutralizeVaultItemServerMetadata`.
- Added read-only SQL verification queries in `docs/security/sql/metadata_zero_knowledge_verification.sql`.

Not implemented in this pass:

- No destructive migration and no legacy-column drop. SQL cannot decrypt user payloads, so blind wiping could cause apparent data loss for existing users.
- No full automatic client migration runner was added; current fallback paths remain as controlled compatibility until that migration is implemented and measured.

## Supabase Edge Function Matrix

All entries below are configured with `verify_jwt = false` in `supabase/config.toml`, so the gateway does not enforce JWTs. Each deployed function must enforce its own auth/rate-limit/CORS boundary.

| Function | Extern erreichbar? | Zweck | Benötigte Auth | Aktuelle Auth im Code | Rate limit | CORS | Secrets / service role | Risiko | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `auth-register` | Yes | OPAQUE-only signup | Public pre-auth | Input validation, unusable GoTrue password, generic errors | `opaque_register` | shared allowlist | service role for auth user creation | Enumeration/abuse if rate-limit regresses | Acceptable with tests |
| `auth-opaque` | Yes | OPAQUE register/login finish | Mixed: register authenticated, login public | Bearer for register, OPAQUE proof for login, 2FA hook | `opaque_login` and 2FA limits | shared allowlist | service role for OPAQUE records/session link | High-value auth path | Acceptable with tests |
| `auth-recovery` | Yes | Recovery email code and reset authorization | Public bootstrap plus optional user auth/2FA | Generic response timing, reset token, bearer for change flows | `recovery_request`, `recovery_verify`, 2FA | shared allowlist | service role, Resend key | Enumeration/reset abuse | Acceptable with tests |
| `auth-reset-password` | Yes | OPAQUE password reset finish | Reset token | Active reset challenge lookup | `opaque_reset` | shared allowlist | service role, Resend key | Unauthorized password reset | Acceptable with tests |
| `auth-session` | Yes | BFF session hydration/logout/OAuth sync; blocks password login | Bearer/session depending action | Bearer validation for OAuth sync; legacy password login blocked | `password_login` for blocked legacy path | shared allowlist | service role/anon | Session confusion | Acceptable with tests |
| `auth-2fa` | Yes | 2FA requirement/challenge/disable | Bearer user auth | `getAuthenticatedUserId`, challenge ownership, central 2FA verifier | central 2FA limits | shared allowlist | service role to verify encrypted TOTP | Brute force / disabling 2FA | Acceptable with tests |
| `account-delete` | Yes | Destructive account deletion | Bearer user auth + RPC owner checks | `auth.getUser(accessToken)`, user-bound RPC | RPC + 2FA path; no standalone throttle found | POST-only shared allowlist | service role for storage cleanup only after auth | Destructive endpoint | Hardened previously; consider explicit rate-limit follow-up |
| `rate-limit` | Yes | Client-visible rate-limit checks | Bearer user auth | Supabase auth client `getUser()` and user binding | This is the rate-limit endpoint | shared allowlist | service role for rate-limit table | Client could probe own limits | Acceptable |
| `webauthn` | Yes | Passkey operations | Action-specific user session | `authorizeWebauthnAction`, bearer extraction, challenge scope binding | Not uniform per action | shared allowlist | service role for challenges/credentials | Passkey abuse if challenge scope regresses | Acceptable with existing WebAuthn policy tests; add per-action rate limits later |
| `admin-team` | Config only, no function directory in public core | Team/admin private area | Admin auth required if deployed | No public source present | Not present | Not present | Unknown | Dangerous if implemented as open stub later | Documented release blocker |
| Premium entries | Config only, no function directories in public core | Billing/support/family/release | Private/premium-specific | No public source present | Not present | Not present | Unknown | Must not ship as open admin/support endpoints | Documented release blocker |

## Tauri Desktop Boundary

| Permission / command | Why needed | XSS impact | Change / Status |
| --- | --- | --- | --- |
| `save_refresh_token`, `load_refresh_token`, `clear_refresh_token` | Desktop refresh token in OS keychain | Renderer can request active refresh token if compromised | Existing keychain isolation; residual renderer-XSS risk documented |
| `save_local_secret`, `load_local_secret`, `clear_local_secret` | Device key and integrity baseline local secrets | Renderer can access allowed per-user key domains | Rust allowlist restricts to `device-key:<uuid>` and `vault-integrity:<uuid>` |
| `dialog:allow-save` + `fs:allow-write-file` | User-selected export writes | Compromised renderer can prompt and write selected file | Kept; export filenames sanitized |
| `opener:*` | OAuth/browser links and item URL opening | `opener:default` also includes reveal-file capability | Changed to `opener:allow-open-url` + `opener:allow-default-urls`; no reveal path |
| `process:allow-restart` | Updater relaunch | Renderer can restart app | Kept because updater UI needs relaunch; release risk documented |
| `deep-link:default` | OAuth callback | Malicious link could race session flow | Rust filters callback prefix; frontend state/PKCE remains required |
| `updater:default` | Signed desktop updates | Update channel is high impact | Minizign public key configured; endpoint is GitHub release JSON |
| Tauri CSP | WebView hardening | XSS containment only | Production CSP avoids `unsafe-eval`; `wasm-unsafe-eval` remains for wasm dependencies |

## Web / PWA Boundary

- Service worker only precaches app shell/build assets and registers a same-origin `/assets/` static route. It does not register Supabase/Auth/Vault API response caching.
- Browser `localStorage` remains limited to preferences, offline identity without tokens, consent, language, unlock attempt state and diagnostics fallback. Web/PWA cannot provide OS-keychain secrecy.
- IndexedDB stores offline snapshots and encrypted credentials; this supports offline unlock but is not XSS/malware resistant once the origin is compromised.
- Clipboard clearing is best-effort and cannot defeat OS clipboard history or malware.
- Desktop refresh tokens are keychain-backed; legacy localStorage auth tokens are purged/ignored by the auth storage path.

## Findings

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| FU-2026-04-28-01 | P1 | Metadata | Trusted quarantine restore could replay legacy server-visible metadata from a local trusted snapshot. | Fixed by central neutralization |
| FU-2026-04-28-02 | P2 | Metadata | Offline queued item upserts accepted caller-supplied metadata before DB trigger normalization. | Fixed in queue policy |
| FU-2026-04-28-03 | P2 | Legacy migration | Full client-side legacy metadata migration remains incomplete. | Documented plan + SQL checks |
| FU-2026-04-28-04 | P2 | Edge Functions | `admin-team` and premium functions are listed in public `config.toml` with `verify_jwt=false` but source is absent from public core. | Release blocker documented |
| FU-2026-04-28-05 | P2 | Edge Functions | `account-delete` and `webauthn` rely on auth/challenge checks but do not show a uniform top-level rate-limit policy for every action. | Follow-up hardening |
| FU-2026-04-28-06 | P2 | Tauri | `opener:default` exposed file reveal capability beyond URL opening need. | Fixed |
| FU-2026-04-28-07 | Info | Web/PWA | Browser storage and IndexedDB remain outside OS-keychain guarantees. | Documented boundary |

## Verification Notes

Updated tests:

- `src/services/vaultMetadataPolicy.test.ts`
- `src/services/__tests__/offlineVaultService.test.ts`
- `src/test/security-hardening-contracts.test.ts`
- `src/test/tauri-capability-contract.test.ts`

Executed checks:

- `npm run security:repo-guard` passed.
- `npm run lint` passed with pre-existing warnings in `SEO.tsx`, `TOTPDisplay.tsx` and `VaultItemDialog.tsx`.
- `npm run test` passed after updating stale offline-row metadata expectations.
- `npm run build` passed with existing chunk-size and dynamic/static import warnings.
- `npm run build:core-only` passed with existing chunk-size and dynamic/static import warnings.
- `npm run test -- --run src/test/security-regression-suite.test.ts src/test/edge-cors-contract.test.ts src/test/account-delete-runtime-hardening.test.ts` passed.
- `npm audit --omit=dev` passed with 0 vulnerabilities.
- `npx tsc --noEmit` passed.
- `cargo test` in `src-tauri` passed.
- `npm run tauri:build:core-only` built the Vite app, Rust release binary and Windows bundles, then failed at update signing because `TAURI_SIGNING_PRIVATE_KEY` is intentionally not present in the local environment.

Not executed:

- `cargo audit` because `cargo-audit` is not installed locally.
- `cargo deny check` because `cargo-deny` is not installed locally.
