# Session And Browser Boundary Update (2026-04-27)

## Session Tokens

- Web/PWA session hydration uses the `auth-session` BFF cookie path.
- The default refresh-cookie lifetime is 14 days unless `SESSION_COOKIE_MAX_AGE_SECONDS` overrides it.
- The browser tab fallback no longer persists access or refresh tokens in `sessionStorage`.
- Older fallback entries are cleared instead of being used for hydration.

## Local Secret Boundary

- Tauri local secrets use OS keychain commands and a Rust-side allowlist for supported secret domains.
- Web/PWA local secrets use IndexedDB plus a non-extractable `CryptoKey` when supported.
- Browser local secret storage is defense-in-depth only. It must not be described as equivalent to an OS keychain or as protection against XSS, malicious extensions, or compromised same-origin JavaScript.
