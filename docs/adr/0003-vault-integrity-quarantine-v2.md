# ADR-0003: Vault Integrity & Quarantine V2

## Status

Accepted as the target integrity architecture. The current implementation now has a productive V2 path for V2-native vaults: item writes use Item-Envelope V2, restore re-encrypts through Item-Envelope V2, Manifest V2 envelopes are persisted server-side, and unlock/manual verification use Manifest V2 when present. The R3 compatibility path remains for vaults that still contain legacy item envelopes.

## Context

The R3 hotfix reduced dangerous false positives: runtime decrypt failures, stale keys, missing server rows, unknown server rows, UI refreshes, search, category views, Authenticator views, and Vault Health rendering no longer create active item quarantine. That was necessary but not sufficient for a password manager. R3 still relied on a local encrypted baseline and did not provide a remote authenticated manifest or full AAD-V2 item binding.

The previous failure mode was a trust-boundary problem. Runtime decrypt errors, baseline drift, missing/unknown records, stale UI state, and real ciphertext manipulation could be displayed as the same "quarantine" concept. Users saw phantom counts such as 17 real vault items versus 21 quarantine entries, and some entries appeared restoreable even when the evidence was only stale diagnostic state.

## Decision

Vault Integrity V2 introduces a central service layer under `src/services/vaultIntegrityV2/`:

- Manifest V2: authenticated vault inventory with `manifestRevision`, `previousManifestHash`, `categoriesHash`, item revisions, key ids, and item envelope hashes.
- Item-AAD V2: every item envelope is bound to `vaultId`, `userId`, `itemId`, `itemType`, `keyId`, `itemRevision`, and `schemaVersion`.
- Decision Engine V2: a pure async evaluator that knows no React, router, storage, or UI state and returns normal, revalidation, safe mode, item quarantine, orphan, missing, sync-pending, or conflict decisions.
- Category integrity: category/structure drift becomes Safe Mode, not item mass quarantine.
- Reconciliation V2: active quarantine, orphan remote, missing recoverable/unrecoverable, stale diagnostics, closed records, and conflicts are separated by canonical identity.
- Snapshot Trust V2: trusted snapshots can be created only from a normal verified state.
- Restore V2: restore requires a matching trusted snapshot, writes a new Item-Envelope V2, updates Manifest V2, and requires re-verification.
- Migration V2: migration is idempotent, requires a verified vault key, rejects active quarantine, rejects ambiguous duplicate rows, and blocks legacy v1/no-AAD rows until they are explicitly re-encrypted.

Operationalization adds three product adapters:

- `productItemEnvelope.ts`: provider-facing item encryption/decryption writes and reads Item-Envelope V2 while preserving legacy read compatibility.
- `serverManifestStore.ts`: loads and persists encrypted Manifest V2 envelopes in `public.vault_integrity_manifests`.
- `runtimeBridge.ts`: connects Manifest V2 evaluation to the existing provider-facing integrity result so unlock and manual verification can consume V2 decisions without UI security logic.

## Security Invariants

Server data is untrusted. The server may store and return encrypted rows and the manifest envelope, but it must not be able to change item inventory, item ciphertext, category structure, or manifest revision without detection.

Local data is trusted only when it was produced after a normal Manifest V2 verification. Snapshots from Safe Mode, item quarantine, conflict, stale cache, incomplete scope, or failed revalidation are not recovery roots.

UI state cannot write quarantine. Search, filters, category switching, Authenticator views, Vault Health, focus refresh, visibility changes, and route changes may only render an already computed decision.

Device-Key state is separate from item integrity. Device-Key activation/deactivation, stale local Device-Key material, missing Device-Key material, wrong master password, passkey failure, and stale offline credentials resolve to lock/revalidation/policy states, not item quarantine.

Active item quarantine requires concrete item evidence after the vault key and manifest have been authenticated. `missing_on_server`, `unknown_on_server`, `orphan_remote`, `stale_baseline_only`, `decrypt_failed`, `wrong_key`, and `policy_stale` are diagnostic-only.

## Consequences

New item formats and crypto versions now have an explicit versioned boundary. Cross-device sync can advance `manifestRevision` and preserve `previousManifestHash` without UI participation. Rollback is detected by comparing the authenticated manifest hash and revision with the local high-water mark.

Migration cannot silently bless legacy or suspicious state. Existing legacy rows must be rewritten through trusted mutation or restore flows before they are Manifest-V2-native. This is stricter than auto-rebaselining and may require a visible migration step, but it avoids making a compromised server snapshot trusted.

Restore is intentionally narrow. It restores only from a trusted local snapshot and re-encrypts through Item-AAD V2. It never uses suspicious remote ciphertext as the source.

Server persistence is deliberately limited. `vault_integrity_manifests` stores the encrypted envelope and non-secret revision metadata under owner-scoped RLS, but the current product write path does not yet provide a single atomic RPC that writes item/category mutations and Manifest V2 together. A failed manifest persist after a legitimate item/category write is a sync/repair state, not evidence of item tampering.

## Tests

The V2 test suite covers:

- Item-AAD field binding and mismatch rejection.
- Item-Envelope V2 encryption/decryption, malformed envelopes, and AEAD failures.
- Manifest V2 authentication and manifest auth-tag tampering.
- Manifest rollback detection.
- Category manipulation to Safe Mode.
- Real encrypted-data manipulation to one active item quarantine.
- Wrong/stale key and Device-Key stale states to revalidation, not quarantine.
- Orphan remote and missing remote as diagnostics, not active quarantine.
- Duplicate active item records as a concrete active finding.
- Legitimate item mutation through AAD V2 and Manifest V2 revision increment.
- Restore from trusted snapshot through AAD V2 and Manifest V2.
- R3 stale diagnostic records without 17-vs-21 phantom active quarantine.
- Idempotent migration and blocked migration for legacy item envelopes.
- Runtime bridge evaluation of an existing server Manifest V2 envelope.
- Runtime bridge mapping of manifest hash mismatch to a precise active V2 quarantine reason.
- Runtime refusal to persist Manifest V2 over legacy item envelopes.
- VaultContext product item encryption now returns an Item-Envelope V2 instead of the legacy item envelope.

## Remaining Boundaries

V2-native vaults now have a productive runtime path, but full R4 is still not claimable until the unlocked browser/Tauri E2E flows pass against a provisioned test account and the remaining legacy migration/write-atomicity work is closed. Existing production vaults that still contain legacy `sv-vault-v1` or legacy no-AAD rows must complete explicit re-encryption before they can be represented as fully migrated Manifest V2 vaults.

The local dev-test-account provisioning currently refuses the configured password because it does not satisfy the local Supabase password policy. That blocks the required unlocked runtime E2E proof. This is a verification blocker, not an integrity-model exception.
