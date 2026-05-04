# Phase 9 UI Integration — Review Summary

**Date:** 2025-01-15  
**Scope:** UI, Quarantine, Safe Mode, Conflict display behind `VITE_VAULT_OP_LOG_PHASE_9_UI_ENABLED`

---

## 1. Changed Files

### New Files
| File | Purpose |
|------|---------|
| `src/services/vaultOpLog/vaultOpLogUiAdapter.ts` | Adapter: `LocalVaultState` → UI models (no secrets) |
| `src/services/vaultOpLog/vaultOpLogUiOrchestrator.ts` | Orchestrator: RPC → State Machine → UI view |
| `src/services/vaultOpLog/vaultOpLogDeviceStore.ts` | Minimal store for `deviceId` + `publicSigningKeyB64Url` |
| `src/contexts/vault/useVaultOpLogUiState.ts` | React hook managing Phase 9 UI state |
| `src/components/vault/VaultOpLogSecurityModeBanner.tsx` | Banner for `normal`, `restricted`, `safeMode`, `lockedCritical` |
| `src/components/vault/VaultOpLogQuarantinePanel.tsx` | Quarantine cards without plaintext |
| `src/components/vault/VaultOpLogConflictPanel.tsx` | Conflict cards with operation IDs |
| `src/services/vaultOpLog/__tests__/vaultOpLogUiAdapter.test.ts` | Adapter unit tests (15 tests) |
| `src/services/vaultOpLog/__tests__/vaultOpLogDeviceStore.test.ts` | Store unit tests (4 tests) |
| `src/services/vaultOpLog/__tests__/vaultOpLogFeatureFlags.test.ts` | Feature flag unit tests (4 tests) |
| `src/components/vault/__tests__/VaultOpLogSecurityModeBanner.test.tsx` | Banner component tests (2 tests) |
| `src/components/vault/__tests__/VaultOpLogQuarantinePanel.test.tsx` | Quarantine panel tests (5 tests) |
| `src/components/vault/__tests__/VaultOpLogConflictPanel.test.tsx` | Conflict panel tests (6 tests) |

### Modified Files
| File | Change |
|------|--------|
| `src/services/vaultOpLog/vaultOpLogFeatureFlags.ts` | Added `isVaultOpLogPhase9UIEnabled()` |
| `src/services/vaultOpLog/index.ts` | Exported Phase 9 modules |
| `src/contexts/vault/useVaultProviderState.ts` | Added `vaultEncryptionKey` state + wipe on lock |
| `src/contexts/vault/useVaultProviderActions.tsx` | Stores `vaultEncryptionKey` on unlock; wires `opLogUiState`; defines placeholder actions |
| `src/services/vaultMasterUnlockService.ts` | Returns `vaultEncryptionKey` from `kdfOutputBytes` |
| `src/services/vaultPasskeyUnlockService.ts` | Returns `vaultEncryptionKey` from `legacyKdfOutputBytes` |
| `src/contexts/vault/vaultContextTypes.ts` | Added `opLogUiView`, `opLogUiLoading`, `opLogUiError`, `opLogUiRefresh`, `opLogRestoreRecord`, `opLogDeleteUntrustedRecord`, `opLogResolveConflict` |
| `src/contexts/vault/buildVaultContextValue.ts` | Accepts `opLogUiState`; maps Phase 9 fields |
| `src/pages/VaultPage.tsx` | Conditionally renders Phase 9 components when `opLogUiView` is present |

### Unchanged Phase 0–8 Artifacts
- `vaultStateMachine.ts` — no changes (only imported for `determineVaultSecurityMode`)
- `vaultOpLogRepository.ts` — no changes
- `vaultOpLogShadowMode.ts` — no changes
- `VaultItemList.tsx` — old productive path untouched
- Legacy integrity/quarantine services (`vaultIntegrityService.ts`, `vaultQuarantineOrchestrator.ts`, etc.) — untouched

---

## 2. UI, Autofill, Export, Search, Clipboard

**None of these were changed or enabled for unverified data.**

- `VaultItemList` remains unchanged; when Phase 9 is off the old path is identical.
- Autofill, Export, Search, and Clipboard remain gated by their existing Phase ≤8 logic.
- Phase 10 gates for these features were intentionally **not** added.

---

## 3. Feature-Flag Protection

- **New flag:** `VITE_VAULT_OP_LOG_PHASE_9_UI_ENABLED`
- **Separate from Shadow Mode:** `isVaultOpLogPhase9UIEnabled()` is independent of `isVaultOpLogShadowModeEnabled()`.
- **Default:** `false` (conservative).
- **Behavior when off:** `useVaultOpLogUiState` returns `null` for `uiView`; no Phase 9 components render; no RPC calls are made; old path is identical.
- **Behavior when on but credentials missing:** Graceful fallback to old path (`uiView: null`).

---

## 4. UI Actions → Signed Operations

| UI Action | Context Method | Intended Signed Operation | Status |
|-----------|----------------|---------------------------|--------|
| Restore | `opLogRestoreRecord(recordId)` | `RestoreFromSnapshot` | Placeholder (Phase 10+) |
| Delete | `opLogDeleteUntrustedRecord(recordId)` | `DeleteUntrustedRemoteRecord` | Placeholder (Phase 10+) |
| Resolve | `opLogResolveConflict(recordId)` | `ResolveConflict` | Placeholder (Phase 10+) |

**No generic "Accept" action exists in the Phase 9 path.**

---

## 5. Test Results

All new tests pass (36 tests total):

- `vaultOpLogUiAdapter.test.ts` — 15 tests ✓
- `vaultOpLogDeviceStore.test.ts` — 4 tests ✓
- `vaultOpLogFeatureFlags.test.ts` — 4 tests ✓
- `VaultOpLogSecurityModeBanner.test.tsx` — 2 tests ✓
- `VaultOpLogQuarantinePanel.test.tsx` — 5 tests ✓
- `VaultOpLogConflictPanel.test.tsx` — 6 tests ✓

---

## 6. Known Pre-existing Failures

None introduced by this change.

---

## 7. Risks

1. **Credential availability:** `vaultEncryptionKey` is only available for master-password unlocks and legacy passkey unlocks. Modern passkey unlocks do not provide the raw `Uint8Array`. Phase 9 UI will not activate in those cases.
2. **Device identity missing:** `vaultOpLogDeviceStore` must be populated during migration (Phase 7). If migration did not run or the store was cleared, Phase 9 UI cannot initialize.
3. **Placeholder actions:** The concrete signed-operation builders (`buildRestoreRecordOperation`, `buildDeleteRecordOperation`) exist, but the pending-queue submission path is not yet wired to the React layer.
4. **State machine mismatch:** If `containerQuarantined` records remain in `recordsById`, `determineVaultSecurityMode` does not count them toward `restricted`/`safeModeRecommended`. This is pre-existing behavior.

---

## 8. Open Questions

1. When should `vaultOpLogDeviceStore` be populated? Currently it is not written during migration; the migration orchestrator would need to call `saveVaultOpLogDeviceIdentity()`.
2. Should `VaultItemList` be explicitly filtered by `opLogVerifiedItemIds` in a future phase, or should the old integrity baseline continue to handle filtering?

---

## 9. Unverified Assumptions

1. `vaultEncryptionKey === kdfOutputBytes` (the raw KDF output before `importMasterKey`). This was inferred from `migrationService.ts` and the unlock flow.
2. `vaultId === user.id`. Used in `useVaultOpLogUiState`.
3. `supabase` client is compatible with `SupabaseRpcClient` interface (runtime cast).

---

## 10. Explicit Answers

1. **Can a quarantined item be displayed normally anywhere?**  
   **No.** Quarantined items appear only in `VaultOpLogQuarantinePanel`. They never appear in `VaultItemList` or any other normal list.

2. **Is there still a button or flow called "Accept"?**  
   **No.** The Phase 9 path uses explicit actions: "Wiederherstellen" (Restore), "Löschen" (Delete), "Auflösen" (Resolve). No button or flow named "Accept" exists.

3. **Is category error treated as a vault lock?**  
   **No.** A category error results in `containerQuarantined` for individual records. It does **not** trigger `lockedCritical`.

4. **Which operation does each UI action generate?**
   - Restore → `RestoreFromSnapshot`
   - Delete → `DeleteUntrustedRemoteRecord`
   - Resolve → `ResolveConflict`
