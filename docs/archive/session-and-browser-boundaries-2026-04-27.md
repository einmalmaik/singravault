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

## Same-Origin XSS Boundary

- Client-side encryption is still the storage boundary for server-side ciphertexts. XSS does not make stored AES-GCM ciphertexts plaintext on the server.
- A compromised same-origin Web/PWA context is not a secret boundary. It can call the same application services as legitimate app code after unlock.
- In an unlocked session, same-origin JavaScript can read rendered vault data, invoke allowed WebCrypto operations, inspect IndexedDB/offline cache data, manipulate sync flows, and trigger clipboard/export/download paths.
- Non-extractable WebCrypto keys reduce direct key export, but they do not stop compromised app JavaScript from asking the key to decrypt data through allowed operations.
- Tauri/OS-keychain storage is stronger than Web/PWA storage for local secret persistence, but it does not protect an already unlocked process from compromised renderer JavaScript or local malware.
- Production hardening therefore relies on safe React text rendering, URL scheme guards, filename sanitization, CSP, and no user-controlled HTML rendering. Trusted Types enforcement was tested and deferred until the remaining service-worker/library sinks can be made compatible without runtime breakage.
