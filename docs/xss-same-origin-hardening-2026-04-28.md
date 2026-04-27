# XSS and Same-Origin Hardening (2026-04-28)

## Scope

This note covers Web/PWA and Tauri renderer XSS boundaries for Singra Vault. It does not change OPAQUE, Auth, 2FA, file E2EE, storage architecture, or Premium/Core ownership.

## Sources Reviewed

- Vault item fields: title, username, password labels/metadata, website URL, notes, custom fields.
- Category fields: name, icon, color.
- TOTP fields: issuer, label/account name, otpauth URI import input.
- File attachment metadata: original filename, MIME type, encrypted manifest metadata.
- Imports and exports: CSV/JSON/vault export filenames and imported values.
- UI surfaces: search, recent items, diagnostics/support data, premium support/admin/billing views, toasts/errors, i18n strings.
- URL inputs: website links, external docs/support/admin/billing links, auth return paths, route/query/hash values, OAuth callback parameters.
- Browser APIs: clipboard/paste input, QR scanner input, decrypted file download names, service-worker notification URLs.
- Rich-content sinks: Markdown/HTML rendering, JSON-LD script tags, SVG sanitization helper.

## Sink Findings

- No active production use of `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `new Function`, string timers, `srcdoc`, or `contentEditable` was found in `src`.
- `src/lib/sanitizeSvg.ts` uses `DOMParser`, but the helper is deprecated and is not an active render path for user-controlled vault data.
- `src/components/SEO.tsx` writes JSON-LD into a script tag. JSON-LD is now serialized with script-breaking characters escaped.
- Vault data is rendered through React JSX/text nodes. There is no production Markdown/HTML renderer for vault item contents.

## URL Rules

- External URL opening goes through `src/platform/openExternalUrl.ts` and allows only `http:`, `https:`, and `mailto:`.
- Auth redirect paths use relative in-app paths only and reject protocol-relative URLs and `/auth` loops.
- Settings return navigation now normalizes `returnTo` and `desktopBackTo` to relative in-app paths.
- Service-worker notification URLs are normalized to same-origin paths before `clients.openWindow()`.
- Premium desktop release links are normalized to GitHub release/download URLs before rendering.

## File and Preview Rules

- Attachments are not rendered inline as HTML, SVG, XML, or PDF.
- The server stores encrypted chunks and an encrypted manifest only; no plaintext preview is generated or uploaded.
- MIME type from upload is stored inside the encrypted manifest but is not treated as a security boundary.
- Decrypted files are written as downloads. Download filenames are sanitized to remove control characters, path separators, HTML-sensitive characters, bidi controls, and reserved Windows basenames.
- Blob URLs are used only for controlled local downloads, not for same-origin HTML preview navigation.

## CSP and Trusted Types

- Production Web/PWA CSP is generated from `vite.config.ts` and mirrored in `vercel.json`.
- Production script policy uses `script-src 'self' 'wasm-unsafe-eval'`; it does not allow general `unsafe-eval` or script `unsafe-inline`.
- `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and `frame-ancestors 'none'` are set.
- Trusted Types enforcement was tested in the production browser build and intentionally deferred. `require-trusted-types-for 'script'` currently breaks service-worker registration and library/Helmet paths that still assign ordinary strings to Trusted Types sinks.
- Development CSP remains intentionally broader for Vite/HMR and must not be used as a production claim.
- Tauri has separate production CSP and `devCsp`; production no longer carries localhost/ws development connect sources.

## Residual Risks

- Browser/PWA same-origin compromise remains a high-impact scenario. A compromised app context can use legitimate app APIs while the vault is unlocked.
- Non-extractable WebCrypto keys reduce raw key export, not malicious use of allowed cryptographic operations.
- Tauri OS-keychain storage is stronger for local persistence, but it does not protect an unlocked renderer process from compromised JavaScript or local malware.
- Complete Premium test-suite health is not claimed here; the known Duress/React double-identity test-infrastructure cleanup remains separate.
