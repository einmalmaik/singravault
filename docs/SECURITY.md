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

The Device-Key state machine is documented in code by `src/services/deviceKeyStateMachine.ts`. The security-relevant states are `unsupported`, `not_configured`, `activation_in_progress`, `active_on_this_device`, `active_but_missing_on_this_device`, `import_required`, `recovery_required`, `activation_failed`, `unlock_failed`, and `unlocked`.

Activation on an already unlocked vault provisions a high-entropy Device Key first, stores it locally, validates readback/derivation, rewraps the UserKey or re-encrypts legacy vault rows, and only then writes `device_key_required` plus the new verifier/wrapper to the profile. A local `DEVICE_KEY_MISSING` during first activation is an activation failure unless provisioning and readback have completed; it must not mark the remote profile protected and must not fall back to a dummy or master-password-only key.

Deactivation lives in `src/services/deviceKeyDeactivationService.ts` and is only allowed from an unlocked device that already has the local Device Key. The flow verifies the current master password plus Device Key by unwrapping and rewrapping the UserKey to master-password-only KDF output. If vault 2FA is enabled, only a current TOTP challenge is accepted; backup codes are not valid for this downgrade. The local Device Key is deleted only after the profile and offline credentials have been persisted as `master_only`.

Unlock for a Device-Key-protected vault requires both the master-password KDF path and local Device-Key availability. Authentication, a Supabase session, or the master password alone only reaches the locked "Device Key required" state. Vault item loading, repair, migration, export, trusted recovery mutation, and quarantine restore require a real unlocked vault key and must not run on missing Device-Key state.

Alternate unlock hooks such as duress/dual-unlock are not Device-Key exceptions. For `device_key_required` vaults, the primary Device-Key-aware unlock path is the only path allowed to release an active vault key.

Tauri stores Device Keys through native commands backed by the OS keychain via Rust `keyring`. On Windows, if the keychain cannot store binary secrets reliably, the desktop runtime uses a DPAPI-protected file under the user's local Singra Vault app data as a fallback. The identifier is scoped by user id and survives normal app updates; deleting app data, resetting the OS keychain, reinstalling in a way that removes local data, or changing OS credentials can require Device-Key import/recovery.

Web and PWA store Device Keys in the browser local secret store: a non-extractable WebCrypto wrapping key in IndexedDB wraps the Device Key payload stored in IndexedDB. This is weaker than an OS keychain and is scoped to the origin/browser profile/PWA storage partition. Another browser profile, private mode, cleared site data, or a PWA/browser storage reset has no Device Key and must import it explicitly.

Device-Key import is available from account security after account login, before vault unlock. That surface may store/import local Device-Key transfer material for the signed-in account, but it must not display vault contents or require an active vault key. Export, disable, and other vault-key-sensitive Device-Key operations remain unavailable while the vault is locked.

Device-Key transfer uses a versioned encrypted envelope plus a high-entropy transfer secret. The transfer secret and envelope must never be logged, sent to telemetry, embedded in URLs, or stored server-side in plaintext. Import refuses malformed, downgraded, extreme-KDF, wrong-secret, and overwrite attempts.

Server compromise limits: `profiles.vault_protection_mode` is the authoritative account/vault-wide Device-Key policy so intentional deactivation on one authorized device is visible to Web, PWA, Tauri, and future clients after refetch/login/focus. Local Device-Key material only proves that this client may possess an old local factor; it must not keep the policy active, enable export, or force Device-Key unlock when the server policy is `master_only`. A compromised server that maliciously downgrades this metadata is still a residual risk; full protection against that class needs authenticated vault metadata or a server-independent signed/AEAD-bound protection-mode record carried with the encrypted UserKey metadata.

## Passkey/WebAuthn

Passkeys are scoped to RP ID and origin. Web, PWA, and Tauri are not assumed to share one passkey surface. PRF support is checked before registration, but actual registration and authentication remain the source of truth.

Passkey unlock is an authentication convenience, not an exception to Device-Key protection. When the server-visible vault policy is `device_key_required`, the client must resolve local Device-Key availability before starting passkey unlock, and the WebAuthn Edge Function must not store or return passkey-wrapped vault-key material. Supporting passkey unlock for Device-Key-protected vaults requires a separate Device-Key-bound proof or enrollment design; until then this path fails closed.

## Integrity and Quarantine

Category drift blocks the vault. Verified ciphertext drift quarantines the affected server-backed items and those items must not be decrypted. Baseline read failures block the vault. There is no auto-rebaseline for untrusted remote drift, category drift, malformed snapshots, or unreadable baselines.

Trusted recovery and Safe Mode use only locally trusted snapshots. Recovery code must not accept manipulated remote data as a trusted source. Quarantine is an integrity state, not an authentication failure; Device-Key-missing is a Device-Key state, not a 2FA failure.

Runtime item decrypt failures are treated separately from persisted integrity drift. They are a revalidation/key-state failure until the integrity service has verified the vault key, snapshot scope, category structure, and item-specific ciphertext evidence. Runtime decrypt errors must not be merged into active item quarantine, persisted, restored, deleted, or counted as manipulated vault items.

Vault Integrity V2 adds an authenticated manifest and context-bound item envelopes in `src/services/vaultIntegrityV2/`. The V2 manifest is encrypted/authenticated with AES-GCM, carries `manifestRevision`, `previousManifestHash`, `categoriesHash`, and the expected item envelope hashes, and is checked against a local high-water mark to detect rollback. Manifest verification is a prerequisite for active item quarantine.

Item-Envelope V2 uses AES-GCM AAD with `vaultId`, `userId`, `itemId`, `itemType`, `keyId`, `itemRevision`, and `schemaVersion`. A ciphertext from another item, user, vault, revision, item type, schema, or key id must fail as an integrity finding after the vault key and manifest have been authenticated. Legacy v1/no-AAD rows require explicit re-encryption before Manifest V2 migration and must not be silently marked trusted.

Quarantine V2 distinguishes active item quarantine from adjacent diagnostics:

- `ciphertext_changed` is active item quarantine only when the item exists in the verified server snapshot and the encrypted payload differs from the trusted baseline.
- `aead_auth_failed`, `item_envelope_malformed`, `item_aad_mismatch`, `item_manifest_hash_mismatch`, `item_revision_replay`, `item_key_id_mismatch`, and `duplicate_active_item_record` are active item quarantine only after Manifest V2 and vault-key authentication have succeeded.
- `missing_on_server` is a missing-remote diagnostic, not active quarantine. It may be recoverable only when a trusted local snapshot contains the item.
- `unknown_on_server` is an orphan-remote diagnostic, not active quarantine. It must not be decrypted or counted as a normal vault item.
- stale or baseline-only references without a current server object and without a trusted local snapshot are diagnostics only and must not show restore actions.

Search, category selection, Authenticator views, Vault Health rendering, focus/visibility refreshes, and other UI state must never create or change quarantine. They may only render the current integrity decision. Device-Key activation/deactivation, stale Device-Key caches, wrong vault keys, stale offline credentials, and passkey/master-password failures must resolve to lock, revalidation, or policy states, never to item quarantine.

Trusted recovery snapshots are created only after a healthy verified vault state. They must not be created from quarantine, Safe Mode, stale cache, incomplete scope, conflict, or failed revalidation states. Restore uses only the trusted local snapshot payload, writes a new Item-Envelope V2 through the mutation path, updates Manifest V2, and verifies that the restored item is no longer quarantined. Restore must never use suspicious server ciphertext as the source of truth.

Current boundary: the V2 service layer, types, cryptographic envelopes, migration gate, reconciliation, mutation, restore, and regression tests are implemented. Existing installed vault rows may still be legacy `sv-vault-v1`/AAD-by-item-id until they are explicitly re-encrypted through trusted mutation or migration flows. The R3 local-baseline runtime path remains as a compatibility path and must keep missing/unknown/stale records diagnostic-only until a vault has completed Manifest V2 migration.

## Runtime Cleanup

Lock clears vault plaintext access and runtime key state. Logout clears account and vault state. JavaScript RAM cannot be proven fully free of temporary plaintext while unlock and rendering are happening, so runtime validation focuses on no persistence, no logs, no network leaks, and cleanup after lock/logout.

Runtime cleanup responsibilities are centralized in `src/services/vaultRuntimeCleanupService.ts` plus the provider state hook. Lock must wipe in-memory Device Key bytes where the browser runtime exposes them, clear session markers, and leave only the metadata required to unlock again.

## Web/PWA/Tauri Boundary

Browser and PWA paths rely on Web Crypto, browser storage, and WebAuthn origin rules. Tauri paths may use native secret storage and native Device-Key derivation. Code must not assume both runtimes expose identical security capabilities.

## Dev/Test Safety

No URL, `localStorage`, `sessionStorage`, or mock-auth bypass may log in a user. Dev-test-account secrets are server-only environment values and must not be exposed in client bundles, examples, tests, fixtures, docs, toasts, or console output.
