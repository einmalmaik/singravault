# Singra Vault Security Model

This is the canonical active security document. Historical audits and dated remediation notes remain supporting evidence, not the source of truth.

## Zero-Knowledge Boundary

Vault item payloads, encrypted category metadata, vault keys, master passwords, Device Key raw material, passkey PRF output, and transfer secrets must not be stored in plaintext in Supabase, browser storage, service-worker caches, logs, URLs, or network payloads.

Account records, billing/subscription state, support metadata, non-secret protection-mode metadata, and operational audit facts are outside the vault zero-knowledge boundary. They must still follow data minimization and access-control rules.

## Key Hierarchy

The master password derives KDF output. Modern vaults unwrap a User Symmetric Key (USK), and vault data remains encrypted under that UserKey. Device-Key-required vaults require both the master-password-derived material and a local Device Key path. Tauri native Device Key paths keep raw Device Key material in Rust/OS-backed storage where available.

## Device Key

`device_key_required` must never fall back to master-password-only unlock. Missing local Device Key material blocks vault unlock with a Device-Key-specific error. Enabling Device Key must not silently create replacement keys on a new device, must roll back local storage on server-state failure where possible, and must only persist non-secret protection metadata server-side.

Device-Key activation lives in `src/services/deviceKeyActivationService.ts`. Unlock preconditions live in `src/services/deviceKeyUnlockOrchestrator.ts` and are consumed by the master-password and passkey unlock flows. React provider hooks must not duplicate or weaken those checks.

## Passkey/WebAuthn

Passkeys are scoped to RP ID and origin. Web, PWA, and Tauri are not assumed to share one passkey surface. PRF support is checked before registration, but actual registration and authentication remain the source of truth.

## Integrity and Quarantine

Category drift blocks the vault. Item drift quarantines affected items and those items must not be decrypted. Baseline read failures block the vault. There is no auto-rebaseline for untrusted remote drift, category drift, malformed snapshots, or unreadable baselines.

Trusted recovery and Safe Mode use only locally trusted snapshots. Recovery code must not accept manipulated remote data as a trusted source. Quarantine is an integrity state, not an authentication failure; Device-Key-missing is a Device-Key state, not a 2FA failure.

## Runtime Cleanup

Lock clears vault plaintext access and runtime key state. Logout clears account and vault state. JavaScript RAM cannot be proven fully free of temporary plaintext while unlock and rendering are happening, so runtime validation focuses on no persistence, no logs, no network leaks, and cleanup after lock/logout.

Runtime cleanup responsibilities are centralized in `src/services/vaultRuntimeCleanupService.ts` plus the provider state hook. Lock must wipe in-memory Device Key bytes where the browser runtime exposes them, clear session markers, and leave only the metadata required to unlock again.

## Web/PWA/Tauri Boundary

Browser and PWA paths rely on Web Crypto, browser storage, and WebAuthn origin rules. Tauri paths may use native secret storage and native Device-Key derivation. Code must not assume both runtimes expose identical security capabilities.

## Dev/Test Safety

No URL, `localStorage`, `sessionStorage`, or mock-auth bypass may log in a user. Dev-test-account secrets are server-only environment values and must not be exposed in client bundles, examples, tests, fixtures, docs, toasts, or console output.
