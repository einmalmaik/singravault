# Zero-Knowledge Branch Audit - 2026-04-28

Branch: `feat/zero-knowledge.hardering`  
Base: `main` at `1646ee9`  
Auditor scope: Auth, OPAQUE, Vault crypto, metadata minimization, Supabase/RLS/Edge Functions, Web/PWA, Tauri, CI/repo hygiene.

## External References Checked

- OWASP ASVS releases: latest stable noted as v5.0.0.
- OWASP Top 10 2021: access control, cryptographic failures, injection, insecure design, misconfiguration, vulnerable components, authentication failures, integrity failures.
- OWASP Password Storage Cheat Sheet: Argon2id is the preferred modern password hashing/KDF baseline; parameters must be versioned and upgradeable.
- OWASP Key Management Cheat Sheet: key lifecycle, storage integrity, compromise handling and zeroization are explicit design requirements.
- RFC 9807 OPAQUE: registration/login split, augmented PAKE server-compromise model, online guessing protection and client enumeration resistance.
- Supabase docs: public-schema RLS must be enabled for browser-exposed data; Edge Functions require explicit auth/CORS handling when JWT verification is disabled.
- Tauri v2 security docs: capabilities merge permissions for a window; CSP is part of the WebView trust boundary and must stay restrictive.

## Repository State

Commands run:

- `git status --short`
- `git branch --show-current`
- `git remote -v`
- `git log --oneline --decorate -n 30`
- `git diff --stat main...HEAD`
- `git diff --name-only main...HEAD`
- `gh pr list --state open --limit 20`
- `gh run list --limit 20`
- `gh issue list --state open --limit 20`

Observed:

- Current branch: `feat/zero-knowledge.hardering`.
- Remote: `origin https://github.com/einmalmaik/singravault.git`.
- Branch delta before this audit: 32 files, mainly CORS, account deletion, security whitepaper, late-April migrations and security tests.
- Open PRs relevant to this audit:
  - #47 preview-origin suffix matching.
  - #46 null-origin credentialed CORS.
  - #45 password reset recovery token.
- Recent CI on `main`: success for `ci`.
- Recent `security` workflow runs on older PRs: failing; the failure details were not inspected beyond `gh run list`.
- Open GitHub issues: none returned by `gh issue list`.

## Threat Model Summary

Assets inside the strict Vault Zero-Knowledge boundary:

- Vault item payloads, including passwords, notes, URLs, usernames, custom fields, TOTP item secrets and item-sensitive metadata.
- Vault/master password and derived Vault/UserKey material.
- Attachment plaintext plus sensitive filename/MIME/manifest fields when attachment E2EE is used.

Assets outside or only partially inside that boundary:

- Account email, user id, session metadata, auth provider metadata.
- Billing/support/subscription/admin metadata.
- Server-side 2FA TOTP verification secret path: encrypted at rest, but server decrypts for verification, so it is not Vault zero-knowledge.
- Recovery/emergency/sharing relationships and timing metadata.
- Storage object sizes, access timing, sync timestamps and technical audit/error metadata.

Primary attackers considered:

- Database reader, malicious admin, compromised service-role key, compromised Edge Function, XSS/same-origin JS, browser extension malware, stolen desktop device, compromised Tauri renderer, network/TLS termination attacker, supply-chain compromise, weak master password, server rollback/replay attacker.

## Findings

| ID | Severity | Area | Finding | Evidence | Risk | Fix Plan | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ZK-2026-04-28-01 | P1 | Edge CORS | Preview suffix allowlist treated broad provider suffixes as hyphen-boundary matches. | `supabase/functions/_shared/cors.ts` accepted `hostname.endsWith("-" + suffix)`. With `vercel.app` configured, `evil-vercel.app` could be treated as allowed. | Credentialed Edge Function CORS exposure to attacker-controlled origins if a broad provider suffix is configured. | Allow hyphen-boundary preview matching only for account/team-owned suffixes with at least three DNS labels; add regression tests. | Fixed |
| ZK-2026-04-28-02 | P2 | Account deletion Edge Function | Raw PostgREST error fields were returned to the browser on `delete_my_account` RPC failures. | `supabase/functions/account-delete/index.ts` returned `error.message`, `error.code`, `details`, `hint`. | Internal schema/RPC details can leak during destructive account lifecycle failures. | Map known errors to stable public codes and statuses only. | Fixed |
| ZK-2026-04-28-03 | P2 | Repo hygiene | Generated loadtest failure artifact was tracked. | `loadtest/tokens.txt.failed.txt` contained generated test account emails and rate-limit output. | Low-grade metadata leakage and a weak precedent for committing generated auth/loadtest artifacts. | Remove file; extend repo guardrails to block `tokens.txt.failed.txt` and `users.txt.failed.txt`. | Fixed |
| ZK-2026-04-28-04 | P2 | Supabase Functions | Multiple functions are configured with `verify_jwt = false`. | `supabase/config.toml` disables gateway JWT verification for auth flows and several premium/admin stubs. | Correct for OPAQUE/recovery entrypoints only if each function verifies tokens/rate limits internally; risky if private functions drift. | Keep as documented boundary; require function-level auth/rate limiting tests before exposing any new function. | Documented |
| ZK-2026-04-28-05 | P2 | Metadata minimization | Client UI still contains legacy plaintext metadata fallback reads. | `VaultItemDialog`, `VaultItemList`, `VaultSidebar`, export/recovery flows read `website_url`, `category_id`, `is_favorite` fallback columns. DB triggers neutralize future writes. | Legacy rows can remain partially metadata-visible until client migration rewrites them; UX fallback may keep legacy dependency alive. | No blind wipe. Continue client migration/re-encryption path, then remove fallback columns and UI fallbacks in a later migration. | Documented |
| ZK-2026-04-28-06 | P2 | Tauri capability scope | Desktop capability includes broad `opener:default`, `fs:allow-write-file`, and `process:allow-restart`. | `src-tauri/capabilities/default.json`. | If renderer is compromised, available plugins increase post-XSS impact. Current custom Rust commands validate keychain/local-secret keys, but plugin scopes remain broad. | Reassess exact filesystem/opener scopes before release; prefer narrower per-command permissions. | Documented |
| ZK-2026-04-28-07 | P2 | Web/PWA boundary | Browser offline identity and UI preferences remain in localStorage/IndexedDB; Web cannot provide OS-keychain isolation. | `authSessionManager.ts`, `deviceKeyService.ts`, `offlineVaultService.ts`. | XSS/extensions/local malware can read browser storage and in-memory plaintext after unlock. | Claims must remain limited: Web/PWA Vault payload E2EE, not malware/XSS-proof local secrecy. | Documented |
| ZK-2026-04-28-08 | Info | Vault crypto | AES-GCM uses 96-bit random IVs, non-extractable WebCrypto AES keys and per-item AAD with versioned envelopes. | `src/services/cryptoService.ts`. | Residual IV collision risk is negligible with CSPRNG; legacy no-AAD payloads require controlled migration. | Keep legacy no-AAD fallback restricted to migration/quarantine paths. | Verified |
| ZK-2026-04-28-09 | Info | OPAQUE | App-password login uses OPAQUE messages; no direct `signInWithPassword` path found in runtime services. | `opaqueService.ts`, `auth-opaque`, `auth-flow-hardening.test.ts`. | OPAQUE does not protect against a malicious client runtime or weak passwords; server can still rate-limit and store OPAQUE records. | Maintain server static key pin and generic auth failures. | Verified |
| ZK-2026-04-28-10 | Info | PWA/XSS | No active `dangerouslySetInnerHTML`, raw `innerHTML`, `document.write`, `eval`, or `new Function` sinks found in `src`. | Static grep on `src`, `index.html`, `vercel.json`. | CSP is still defense-in-depth; same-origin JS compromise remains catastrophic after unlock. | Keep CSP without `unsafe-eval` in production and avoid rich HTML rendering. | Verified |

## Zero-Knowledge Claim

Current defensible claim:

> Vault-Inhalte werden clientseitig verschlüsselt; Server dürfen keine Vault-Payloads, Master-Passwörter oder Vault-Decryption-Keys sehen. Einige technische Account-, Auth-, Sync-, Recovery-, Billing- oder Support-Metadaten bleiben außerhalb dieser engen Vault-Zero-Knowledge-Grenze und werden minimiert.

This branch supports Vault-content zero-knowledge for new writes when:

- OPAQUE remains the only app-password auth path.
- Vault payload encryption stays client-side.
- Future `vault_items` writes are neutralized by DB triggers.
- Category metadata writes use encrypted `enc:cat:v1:*` values.
- Attachment E2EE metadata rules are preserved.

It does not prove 100% zero-knowledge for the whole product because account, session, billing/support, 2FA verification, recovery/emergency relationships, sync revisions, storage size/timing and some legacy migration metadata remain server-visible.

## Implementation Changes From This Audit

- Hardened preview CORS suffix matching against broad provider suffix bypass.
- Sanitized `account-delete` RPC error responses.
- Removed generated loadtest failed-token artifact.
- Extended repo secret guardrails for failed token/user loadtest artifacts.
- Added/updated regression tests for CORS and account-delete error sanitization.
- Updated `package-lock.json` with `npm audit fix` and pinned `serialize-javascript` via npm `overrides` to remove the remaining production audit finding from the PWA/workbox dependency chain.

## Tests / Verification Notes

Verification run:

- `npm run security:repo-guard` - passed after artifact removal and guard update.
- `npx vitest run src/test/edge-cors-contract.test.ts supabase/functions/_shared/cors.test.ts src/test/account-delete-runtime-hardening.test.ts` - passed, 12 tests.
- `npx vitest run src/test/security-regression-suite.test.ts src/test/edge-cors-contract.test.ts supabase/functions/_shared/cors.test.ts` - passed, 21 tests.
- `npm run lint` - passed with existing warnings in `SEO.tsx`, `TOTPDisplay.tsx` and `VaultItemDialog.tsx`.
- `npm run test` - passed after updating the stale null-origin CORS expectation; the first run timed out before output and the second exposed that stale expectation.
- `npm run build` - passed with existing chunk-size/dynamic-import warnings.
- `npm run build:core-only` - passed with existing chunk-size/dynamic-import warnings.
- `npm audit --omit=dev` - passed after dependency remediation.
- `npm audit` - still reports dev-only findings through `jsdom`/`@tootallnate/once` and `vite-plugin-top-level-await`/`uuid`; the available automatic fixes require forceful breaking-version changes and were not applied in this security hardening pass.
- `cargo audit` - not available in the local toolchain.
- `cargo deny check` - not available in the local toolchain.

## Migration / Data Risk

- No new database migration was added by this audit.
- Existing metadata migrations intentionally avoid blind plaintext wipes for legacy rows that may not have completed client-side re-encryption.
- Account deletion storage cleanup remains split: authoritative DB deletion in RPC, attachment object cleanup through the Storage API in the Edge Function.
- Rollback risk: reverting the CORS patch can reintroduce credentialed preview-origin exposure if a broad provider suffix is configured.
