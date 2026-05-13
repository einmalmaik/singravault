# Vault Operation Log — Legacy-Path Inventory and Phase Plan

This document maps every path that the new operation-log-based
integrity system (ADR-0004) will eventually replace, and records the
phase in which each path is expected to change or be removed. It is a
working document, not a finished plan, and it MUST stay accurate as
the feature branch progresses.

All file and line references are valid against the branch base
`feature/vault-operation-log-quarantine-integrity@<base>`.

## 1. Legacy integration and integrity runtime (R3 + Manifest V2)

These modules decide whether a remote change is integrated, whether to
rebaseline, and whether the vault is healthy / quarantine / blocked.
They are the primary target of phase 6.

| Path | Role today | Phase to change |
|---|---|---|
| `src/services/vaultIntegrityService.ts` | R3 local snapshot digest, baseline compare, decision mapping | removed in phase 7 |
| `src/services/vaultIntegrityRuntimeService.ts` | Runtime orchestrator, rebaseline gate, decision logging | replaced by new `vaultSyncService` + `vaultStateMachine` in phase 6, removed in phase 7 |
| `src/services/vaultIntegrityDecisionEngine.ts` | Canonical decision mapping, `canRebaselineRecentLocalMutation`, `canRebaselineTrustedMutation` | replaced in phase 3 by new state machine, removed in phase 7 |
| `src/services/integrityBaselineStore.ts` | Local baseline / snapshot digest persistence | removed in phase 7 |
| `src/services/vaultIntegrityV2/runtimeBridge.ts` | Manifest V2 runtime bridge, snapshot-hash high-water-mark, manifest persist retry | removed in phase 7, functionality moves to `vaultStateMachine` + hash-chain head |
| `src/services/vaultIntegrityV2/decisionEngine.ts` | Manifest V2 decisions | removed in phase 7 |
| `src/services/vaultIntegrityV2/manifestCrypto.ts` | Manifest V2 AEAD and manifest AAD | superseded in phase 1 (record AEAD v1 + AAD v1), file removed in phase 7 |
| `src/services/vaultIntegrityV2/manifestEnvelopeCacheStore.ts` | Manifest V2 envelope cache | removed in phase 7 |
| `src/services/vaultIntegrityV2/manifestHighWaterMarkStore.ts` | Manifest V2 HWM persistence | replaced in phase 4 by `lastVerifiedVaultHead` store, removed in phase 7 |
| `src/services/vaultIntegrityV2/manifestPersistRetryStore.ts` | Manifest V2 persist retry marker | removed in phase 7 |
| `src/services/vaultIntegrityV2/mutationPipeline.ts` | Manifest V2 CAS mutation pipeline | replaced in phase 6 by new `submit_vault_operation` client wrapper |
| `src/services/vaultIntegrityV2/productItemEnvelope.ts` | Item-Envelope V2 adapter for product paths | replaced in phase 6 by `cryptoRecordService`-backed adapter |
| `src/services/vaultIntegrityV2/quarantineReconciler.ts` | Manifest V2 quarantine reconciliation | replaced in phase 3 by `quarantineService`, removed in phase 7 |
| `src/services/vaultIntegrityV2/recoveryOrchestrator.ts` | Manifest V2 restore | replaced in phase 4 by `trustedSnapshotService`, removed in phase 7 |
| `src/services/vaultIntegrityV2/safeModeDecrypt.ts` | Recovery-only decrypt helper | replaced in phase 4 by `safeModeService`, removed in phase 7 |
| `src/services/vaultIntegrityV2/serverManifestStore.ts` | `apply_vault_mutation_v2` RPC wrapper | removed in phase 6; replaced by `submit_vault_operation` wrapper |
| `src/services/vaultIntegrityV2/snapshotTrust.ts` | Manifest V2 snapshot trust | replaced in phase 4 by `trustedSnapshotService`, removed in phase 7 |
| `src/services/vaultIntegrityV2/categoryIntegrity.ts` | Category / structure drift → Safe Mode | replaced in phase 6 by per-category record verification |
| `src/services/vaultIntegrityV2/migration.ts` | Manifest V2 migration | replaced in phase 5 by new migration service, removed in phase 7 |

## 2. Time-window trust heuristics

Binding for phase 6: the TTL-based "recent local mutation" window is
removed. Authoritativeness comes from `opId`, `baseRecordVersion`,
`previousRecordHash` and a signed, idempotent RPC.

| Path | Symbol | Phase |
|---|---|---|
| `src/services/offlineVaultService.ts:31` | `LOCAL_WRITE_CACHE_TTL_MS = 60_000` | removed in phase 6 |
| `src/services/offlineVaultService.ts:33-154` | `RecentLocalMutationWindow`, `recentLocalMutationsByUser`, `extendRecentLocalMutationWindow` | removed in phase 6 |
| `src/services/vaultIntegrityDecisionEngine.ts` | `canRebaselineRecentLocalMutation` | removed in phase 3 |
| `src/services/vaultIntegrityRuntimeService.ts:914-924` | `recentLocalRebaselineAllowed` rebaseline branch | removed in phase 6 |

## 3. Rebaseline paths

Binding: automatic rebaseline on unknown-but-decryptable remote change
is forbidden. Remote changes are only integrated when a signed
operation from a trusted device covers them.

| Path | Role | Phase |
|---|---|---|
| `src/services/vaultIntegrityDecisionEngine.ts` | `canRebaselineTrustedMutation` | removed in phase 3 |
| `src/services/vaultIntegrityRuntimeService.ts:652-656` | `canRebaselineTrustedMutation(...)` call | removed in phase 6 |
| `src/services/vaultIntegrityRuntimeService.ts:661-666` | Quarantine bypass when trusted rebaseline allowed | removed in phase 6 |
| `src/services/vaultIntegrityRuntimeService.ts:740-763` | `blocked` / `quarantine` / non-tamper branches that respect `trustedRebaselineAllowed` | removed in phase 6 |
| `src/services/vaultIntegrityRuntimeService.ts:925-930` | `persistIntegrityBaseline` after recent-local-rebaseline | removed in phase 6 |

## 4. Direct `vault_items` / `categories` writes

Binding: phase 6 removes these runtime writes. Phase 2 adds the RPC
that replaces them. Phase 6 and 7 clean up. Legacy migration helpers
(`legacyVaultRepairService`, `vaultKdfRepairService`,
`legacyVaultMetadataMigrationService`,
`vaultQuarantineRecoveryService`, `vaultMasterUnlockService`,
`deviceKeyActivationService`) may keep read/write access to legacy
tables during phase 5 for the one-shot migration, but they MUST NOT be
reachable from the normal unlock / sync / autofill / export path after
phase 6.

### 4.1 Product writes (must be replaced in phase 6)

| Path | Site |
|---|---|
| `src/components/vault/VaultItemDialog.tsx` | `.from('vault_items').upsert` for save, `.delete()` for delete |
| `src/components/vault/CategoryDialog.tsx` | `.from('vault_items').upsert` and `.delete()` for category-linked items; `.from('categories').upsert` for category save; `.from('categories').delete()` for category delete |
| `src/components/vault/VaultSidebar.tsx` | `.from('categories').update` for metadata migration |
| `src/components/settings/DataSettings.tsx` | `.from('vault_items').insert` for import, `.from('vault_items').select` for export |
| `src/components/settings/AccountSettings.tsx` | `.from('vault_items').select` for counts and export |

### 4.2 Offline snapshot and RPC wrapper

| Path | Site | Phase |
|---|---|---|
| `src/services/offlineVaultService.ts:~970-985` | `.from('vault_items').select` and `.from('categories').select` for snapshot | phase 6: replaced by `get_vault_changes_since` |

### 4.3 Legacy / KDF / migration helpers (allowed to read during phase 5, removed in phase 7)

| Path | Role |
|---|---|
| `src/services/vaultMasterUnlockService.ts` | KDF upgrade re-encrypts `vault_items` + `categories` |
| `src/services/vaultKdfRepairService.ts` | KDF repair scans + updates `vault_items` and `categories` |
| `src/services/legacyVaultRepairService.ts` | Legacy v1 repair reads + updates `vault_items` and `categories` |
| `src/services/legacyVaultMetadataMigrationService.ts` | Metadata minimisation on `vault_items` |
| `src/services/vaultQuarantineRecoveryService.ts` | Quarantine recovery upsert / delete / existence check on `vault_items` |
| `src/services/deviceKeyActivationService.ts` | Device-Key rewrap of `vault_items` and `categories` |

## 5. Global vault blocking on a category problem

Binding: a broken category never blocks the whole vault. The category
record goes to `quarantinedTampered` / `quarantinedUnreadable` /
`quarantinedMissingWithoutDelete`; items that reference it become
`containerQuarantined`. The vault mode stays `restricted`, not
`safeMode` and not `lockedCritical`.

| Path | Trigger today | Phase |
|---|---|---|
| `src/services/vaultIntegrityV2/categoryIntegrity.ts` | Any category / structure drift → Safe Mode | phase 6: replaced by per-category record verification |
| `src/services/vaultIntegrityRuntimeService.ts` (category drift branches) | Safe Mode / blocked on category drift | phase 6 |
| `src/services/vaultIntegrityDecisionEngine.ts` (category branches) | Drift → blocked decision | phase 6 |

## 6. UI, autofill, export, search, clipboard

Phase 6 refactors these to consume only `verified` records (and
optionally `containerQuarantined` items with a visible warning).
Phase 8 adds property tests that prove quarantined records never reach
any of these paths.

| Path | Phase |
|---|---|
| `src/components/vault/VaultList*.tsx` and the list-rendering call sites | phase 6 |
| Autofill surfaces in `src/extensions/` and Tauri autofill bridges | phase 6 |
| `src/services/vaultExportService.ts`, `src/services/exportFileService.ts`, `src/components/settings/DataSettings.tsx` | phase 6 |
| Search index builders (currently derived from decrypted plaintexts) | phase 6 |
| Clipboard copy call sites (`src/services/clipboardService.ts` consumers) | phase 6 |

## 7. Supabase-side legacy artefacts

Phase 2 introduces the new `vault_records`, `vault_operations`,
`vault_device_trust_records` and `submit_vault_operation` /
`get_vault_changes_since` / `get_vault_records_by_ids` /
`get_vault_head` RPCs. Phase 7 blocks direct writes on the old
content tables at the policy level.

| Artefact | Phase |
|---|---|
| `public.vault_items` table (content rows) | phase 7: direct writes denied via RLS / policy; table itself kept read-only until phase 8 migration is verified end-to-end, then dropped in a follow-up migration |
| `public.categories` table (content rows) | same as `vault_items` |
| `public.vault_integrity_manifests` table | phase 7: dropped once no client reads Manifest V2 |
| `public.apply_vault_mutation_v2` RPC | phase 7: dropped |

## 8. Phase plan

Each phase ends with a green targeted test run and a documented
runtime check on Web and Tauri. No phase removes legacy code until the
successor path is proven.

- **Phase 0 (this session).** Branch, ADR-0004, inventory,
  canonical-JSON / AAD / hash / opHash test vectors. No product
  change.
- **Phase 1 (this session).** Pure `cryptoRecordService`,
  `operationSigningService`, `deviceTrustService` with complete unit
  tests. Not referenced from any product path. No new dependency.
- **Phase 2.** Supabase migration for `vault_records`,
  `vault_operations`, `vault_device_trust_records`, RLS, constraints,
  and the `submit_vault_operation` / `get_vault_changes_since` /
  `get_vault_records_by_ids` / `get_vault_head` RPCs. No runtime
  change.
- **Phase 3.** `vaultStateMachine`, `vaultSyncService`,
  `quarantineService` as pure modules with fixture-driven tests.
  Feature-flag `vault.op-log.runtime` (default `false`) wires them in
  behind `VaultContext` but never reaches UI.
- **Phase 4.** `trustedSnapshotService`, `safeModeService`,
  hash-chain head persistence, conflict model.
- **Phase 5.** `migrationService`: pre-migration signed snapshot,
  legacy read, new record creation, initial create-operations, first
  trusted device registration, idempotent RPC commit, end-state
  verification, first new trusted snapshot. Feature-flag off by
  default.
- **Phase 6.** Product integration: `VaultContext` reads/writes via
  new services behind the feature flag. Autofill, export, search,
  clipboard gated on `verified`. TTL window removed. Rebaseline paths
  removed. Direct `vault_items` / `categories` writes removed from
  product code.
- **Phase 7.** Legacy removal: R3 files, Manifest V2 files, legacy
  helper services, legacy RPC wrappers, legacy stores. RLS denies
  direct writes to old content tables.
- **Phase 8.** Property / negative / scale tests (100 / 1k / 10k
  records), multi-tab leader-election tests, CI secret-scanning and
  dependency-risk updates.

## 9. Open items to revisit before phase 2

- Whether `previous_op_hash` is enforced server-side (cheap gap
  detection, stronger rollback signal) or only surfaced for the client
  to verify.
- Whether the existing `vault_sync_head` / `sync_heads` construct from
  `20260427212000_harden_emergency_access_and_sync_heads.sql` is
  reused as part of `get_vault_head` or replaced cleanly.
- How attachments (`vault_attachments`, chunked bucket model) integrate
  with the record/operation model. Target: metadata rows become
  records; chunk bucket stays but its chunk index becomes a record
  field.
- How family collections and emergency access currently coupled to
  `vault_items` participate. Target: treated as additional trust
  lists plus per-collection operation streams, handled after
  single-user parity.
