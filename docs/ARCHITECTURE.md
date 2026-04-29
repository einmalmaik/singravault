# Singra Vault Architecture

This is the canonical active architecture document. Older files under `docs/` are historical notes unless they are explicitly referenced from here.

## Vault Runtime Modules

| Area | Owner |
|---|---|
| React gateway | `src/contexts/VaultContext.tsx` |
| Public vault provider API | `src/contexts/vault/vaultContextTypes.ts` |
| Callback binding and provider delegation | `src/contexts/vault/useVaultProviderActions.tsx` |
| Provider state and local state helpers | `src/contexts/vault/useVaultProviderState.ts` |
| Provider lifecycle effects | `src/contexts/vault/useVaultLifecycleEffects.ts` |
| Context value assembly | `src/contexts/vault/buildVaultContextValue.ts` |
| Session markers | `src/services/vaultRuntimeFacade.ts` |
| Runtime cleanup and auto-lock persistence | `src/services/vaultRuntimeCleanupService.ts` |
| Offline credentials and integrity snapshot loading | `src/services/offlineVaultRuntimeService.ts` |
| Initial vault setup | `src/services/vaultSetupOrchestrator.ts` |
| Route policy | `src/services/accountVaultRoutePolicy.ts` |
| Device Key activation and rewrap | `src/services/deviceKeyActivationService.ts` |
| Device-Key-required unlock preconditions | `src/services/deviceKeyUnlockOrchestrator.ts` |
| Vault 2FA gate | `src/services/vaultUnlockOrchestrator.ts` |
| Master-password unlock flow | `src/services/vaultMasterUnlockService.ts` |
| Passkey unlock and wrapping material | `src/services/vaultPasskeyUnlockService.ts` |
| UserKey migration and verifier backfill | `src/services/vaultUserKeyMigrationService.ts` |
| Legacy KDF repair | `src/services/vaultKdfRepairService.ts` |
| Integrity decisions | `src/services/vaultIntegrityDecisionEngine.ts` |
| Integrity runtime orchestration | `src/services/vaultIntegrityRuntimeService.ts` |
| Quarantine summaries and decrypt guard | `src/services/vaultQuarantineOrchestrator.ts` |
| Trusted recovery and quarantine mutations | `src/services/vaultRecoveryOrchestrator.ts` |
| Legacy repair helpers | `src/services/legacyVaultRepairService.ts` |

## Change Rules

`src/contexts/VaultContext.tsx` stays a gateway: define the context, export the provider, export `useVault`, and keep the public API stable. `src/contexts/vault/useVaultProviderActions.tsx` binds callbacks and delegates to services; it must not become a second VaultContext monolith.

Auth-state changes belong in `AuthContext` or dedicated auth services. Vault-unlock changes belong in `vaultMasterUnlockService`, `vaultPasskeyUnlockService`, `vaultUnlockOrchestrator`, or `deviceKeyUnlockOrchestrator`. Device-Key activation belongs in `deviceKeyActivationService`. Integrity and quarantine decisions must stay in their decision/orchestrator services.

File-size guardrails: `VaultContext.tsx` should remain below 150 lines, `useVaultProviderActions.tsx` below 700 lines, and no new runtime module should grow past 900 lines. If one of those limits is reached, split by responsibility before adding behavior.

Account Settings must not require vault unlock. Vault Settings and vault data access must use `accountVaultRoutePolicy` and the vault lock state.

## Dev Test Account

The dev test account is local-environment driven. Server-only values such as passwords, master passwords, and service-role keys must be used only by trusted Node scripts such as `scripts/dev/ensure-dev-test-account.mjs`. Client code may only read `VITE_DEV_TEST_ACCOUNT_UI`; no password, master password, Device Key material, or service key may use a `VITE_` prefix.

## Required Checks

For vault/auth/device-key/quarantine changes run targeted tests first, then the full `npm run test` at the end. Changes touching runtime imports, React contexts/hooks, routing, settings pages, Vite aliases, Premium/Core boundaries, or Tauri/Web paths require opening `/vault/settings` and the changed route in a real browser or Tauri runtime and checking the console for provider/hook/import identity errors.
