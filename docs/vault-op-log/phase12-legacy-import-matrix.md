# Phase 12 Legacy Import Matrix

Stand: 2026-05-06

Diese Matrix dokumentiert den aktuellen Repo-Audit-Stand nach der Umstellung der Quarantäne-Actions und dem neuen OpLog-CRUD-Service. Ein Eintrag mit `Produktivpfad = ja` bedeutet, dass der Code noch aus normalem Runtime-/UI-Code erreichbar ist und deshalb für Phase 12 bewertet werden muss.

| Legacy-Datei / Symbol | Importer | Call-Site | Produktivpfad? | Entscheidung | Test |
| --- | --- | --- | --- | --- | --- |
| `vaultIntegrityRuntimeService.ts` / `finalizeVaultUnlockIntegrity` | `useVaultProviderActions.tsx` | Unlock-Finalizer | ja | Vorläufig behalten: delegiert auf V2-Bridge, alte V1-Rebaseline ist entfernt. Bleibt Restblocker, weil normaler Unlock noch nicht direkt aus OpLog-State freigibt. | `VaultContext.test.tsx` |
| `vaultIntegrityRuntimeService.ts` / `refreshVaultIntegrityBaseline`, `verifyVaultIntegrity` | `useVaultIntegrityActions.ts` | manuelle Verify-/Refresh-Actions | ja | Behalten als prüfender Kompatibilitätspfad; keine alte Snapshot-Rebaseline. Ablösung durch OpLog-Read-Model offen. | `VaultContext.test.tsx` |
| `vaultIntegrityV2/runtimeBridge.ts` | `vaultIntegrityRuntimeService.ts`, `vaultQuarantineRecoveryService.ts` | Unlock-/Quarantäne-Klassifizierung | ja | Isoliert als verbleibende Manifest-V2-Brücke. Kein direkter Write, aber nicht finaler Phase-12-Zielzustand. | `VaultContext.test.tsx`, `vaultQuarantineRecoveryService.test.ts` |
| `vaultRecoveryOrchestrator.ts` / trusted snapshot reads | `useVaultProviderActions.tsx`, `useVaultIntegrityActions.ts`, `runtimeBridge.ts` | Safe Mode und Recovery-State | ja | Nur read-only Recovery/Snapshot-State behalten. Alte Quarantäne-Write-Exports sind entfernt. | `vaultRecoveryOrchestrator.test.ts` |
| `vaultQuarantineRecoveryService.ts` / `buildQuarantineResolutionMap` | `useVaultProviderState.ts` | UI-Quarantäne-Action-State | ja | Behalten als UI-Projektion. `canAcceptMissing` und direkte Restore/Delete-Writes entfernt. | `vaultQuarantineRecoveryService.test.ts`, `security-hardening-contracts.test.ts` |
| alte Quarantäne-Write-Actions | keine Produktivimporte | alte Restore/Delete/Accept UI-Actions | nein | Gelöscht/entfernt. Restore/Delete/Resolve laufen nicht mehr über Legacy-Orchestrator; ohne verifizierten Kontext fail-closed. | `VaultQuarantineActions.test.tsx`, `VaultItemList.test.tsx` |
| `LEGACY_VAULT_WRITE_BLOCKED_MESSAGE` / `vaultLegacyWriteBlocker.ts` | `VaultItemDialog.tsx`, `CategoryDialog.tsx`, `DataSettings.tsx`, `legacyVaultMetadataMigrationService.ts` | UI Create/Update/Delete/Import und Legacy-Migration-Writes | ja | Behalten als sichere Blockade, bis UI-CRUD vollständig an `vaultOpLogCrudService.ts` angebunden ist. Kein Trust-Fallback. | `security-hardening-contracts.test.ts` |
| `LOCAL_WRITE_CACHE_TTL_MS`, `RecentLocalMutationWindow`, `canRebaselineRecentLocalMutation`, `[VaultIntegrity]` Logs | keine Produktivimporte | alte TTL/Rebaseline/Legacy-Logs | nein | Entfernt aus `src`-Produktivpfaden. Nur historische Dokumente erwähnen sie. | `rg` gegen `src` |
| direkte Runtime-Writes auf `vault_items`/`categories` | Dialoge, DataSettings | Create/Update/Delete/Import | nein, blockiert | Unsichere Legacy-Writes bleiben blockiert. Neuer CRUD-Service existiert, UI-Anbindung ist noch Restblocker. | `security-hardening-contracts.test.ts`, `vaultOpLogCrudService.test.ts` |

## Ergebnis

Phase 12 ist weiter, aber nicht vollständig abgeschlossen: alte Quarantäne-Write-Pfade sind entfernt, Tombstone-Deletes sind signierte Payload-Operationen, und der zentrale CRUD-Service ist unit-getestet. Der normale Unlock-/UI-Schreibpfad enthält aber weiterhin Legacy-/V2-Brücken und blockierte Legacy-Write-UI statt vollständiger OpLog-CRUD-Anbindung.
