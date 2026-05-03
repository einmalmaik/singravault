# VaultContext Refactor Completion Map (2026-04-29)

This archived mapping records where the former `useVaultProviderActions.tsx`
responsibilities moved. The active canonical module map is in `docs/ARCHITECTURE.md`.

| Former responsibility | New owner |
|---|---|
| React provider state, refs, local state helpers | `src/contexts/vault/useVaultProviderState.ts` |
| Mount/session restore/online/auto-lock/activity effects | `src/contexts/vault/useVaultLifecycleEffects.ts` |
| Context value object assembly | `src/contexts/vault/buildVaultContextValue.ts` |
| Initial master-password setup and default vault creation | `src/services/vaultSetupOrchestrator.ts` |
| Cached credentials and snapshot loading | `src/services/offlineVaultRuntimeService.ts` |
| Lock/session marker cleanup and Device Key byte wiping | `src/services/vaultRuntimeCleanupService.ts` |
| Device Key activation, UserKey rewrap, rollback | `src/services/deviceKeyActivationService.ts` |
| Master-password unlock, KDF upgrade and legacy unlock flow | `src/services/vaultMasterUnlockService.ts` |
| Passkey unlock and passkey wrapping material | `src/services/vaultPasskeyUnlockService.ts` |
| UserKey migration and verifier backfill | `src/services/vaultUserKeyMigrationService.ts` |
| Legacy broken-KDF repair scan | `src/services/vaultKdfRepairService.ts` |
| Integrity unlock/finalize/rebaseline/verify runtime | `src/services/vaultIntegrityRuntimeService.ts` |
| Trusted recovery, Safe Mode support and quarantine mutations | `src/services/vaultRecoveryOrchestrator.ts` |
