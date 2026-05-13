# Phase 11 Inventar — Alte Runtime-Logik

Dieses Dokument listet alle identifizierten alten Runtime-Pfade auf, die in Phase 11 entfernt, neutralisiert oder auf Migration-Service beschränkt wurden.

## Legende

- **Entfernen**: Code wurde gelöscht oder durch No-Op ersetzt.
- **Neutralisiert**: Funktion existiert noch, trifft aber keine Runtime-Trust-Entscheidung mehr (z. B. gibt nur Diagnose zurück, blockiert nicht).
- **Migration-Service**: Code wurde in Legacy-Migration-Service verschoben und darf nur von dort importiert werden.
- **Behalten**: Code bleibt unverändert, weil er zum neuen Modell gehört.

## Inventar

| Datei | Symbol / Bereich | Alte Logik | Status | Begründung |
|---|---|---|---|---|
| `src/services/offlineVaultService.ts` | `LOCAL_WRITE_CACHE_TTL_MS` | TTL-Konstante | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `RecentLocalMutationWindow` | Interface für TTL-Fenster | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `recentLocalMutationsByUser` | Map für aktive TTL-Fenster | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `recordRecentLocalMutation()` | Setzt TTL-Fenster nach lokaler Mutation | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `getRecentLocalMutationWindow()` | Holt TTL-Fenster | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `isRecentLocalVaultMutation()` | Prüft, ob Mutation im TTL-Fenster liegt | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/offlineVaultService.ts` | `applyRecentLocalMutations()` | Merge-Logik für TTL-Fenster | **Entfernt** | Zeitfenster-basiertes Trust ist verboten. |
| `src/services/vaultIntegrityDecisionEngine.ts` | `canRebaselineTrustedMutation()` | Automatische Rebaseline bei trusted mutation | **Entfernt** | Rebaseline ist verboten. |
| `src/services/vaultIntegrityDecisionEngine.ts` | `canRebaselineRecentLocalMutation()` | Automatische Rebaseline bei recent local mutation | **Entfernt** | Rebaseline ist verboten. |
| `src/services/vaultIntegrityDecisionEngine.ts` | `hasTrustedDrift()` | Hilfsfunktion für Rebaseline | **Entfernt** | Rebaseline ist verboten. |
| `src/services/vaultIntegrityDecisionEngine.ts` | `detectUnreadableCategories()` | Löste Kategorie-Globalblockade aus | **Neutralisiert** | Darf Vault nicht mehr global blockieren; Zustände kommen aus neuer State Machine. |
| `src/services/vaultIntegrityService.ts` | `verifyVaultSnapshotIntegrity()` | Snapshot-Digest-basierte Verifikation | **Entfernt** | Snapshot-Digest ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityService.ts` | `inspectVaultSnapshotIntegrity()` | Snapshot-Digest-basierte Inspektion | **Entfernt** | Snapshot-Digest ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityService.ts` | `persistIntegrityBaseline()` | Persistiert alte Baseline | **Entfernt** | Baseline ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityService.ts` | `persistTrustedMutationIntegrityBaseline()` | Persistiert Baseline für trusted mutation | **Entfernt** | Baseline ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityService.ts` | `computeVaultSnapshotDigest()` | Digest-Berechnung | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `buildItemDigestMap()` | Hilfsfunktion für Digest | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `buildCategoryDigestMap()` | Hilfsfunktion für Digest | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `detectItemDigestDrift()` | Drift-Erkennung via Digest | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `detectCategoryDigestDriftIds()` | Drift-Erkennung via Digest | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `StoredIntegrityBaselineV1/V2` | Typen für alte Baseline | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityService.ts` | `VaultIntegrityBaselineError` | Fehlerklasse für Baseline | **Entfernt** | Nur noch in Migration-Service erlaubt. |
| `src/services/vaultIntegrityRuntimeService.ts` | `refreshVaultIntegrityBaseline()` | Vollständige Rebaseline-/Downgrade-Logik | **Entfernt** | Alte Runtime-Logik entfernt. |
| `src/services/vaultIntegrityRuntimeService.ts` | `shouldDowngradeCrossDeviceV2BaselineDrift()` | Cross-Device-Digest-Trust | **Entfernt** | Digest-Trust ist verboten. |
| `src/services/vaultIntegrityRuntimeService.ts` | `canTrustManualRemoteV2Bootstrap()` | Entschlüsselbar = akzeptieren | **Entfernt** | Entschlüsselbarkeit allein ist kein Trust. |
| `src/services/vaultIntegrityRuntimeService.ts` | `persistMissingOrLegacyBaseline()` | Baseline-Persistenz in Runtime | **Entfernt** | Baseline ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityRuntimeService.ts` | `canPersistIntegrityBaselineImmediately()` | Hilfsfunktion für Baseline | **Entfernt** | Baseline ist keine Runtime-Trust-Quelle mehr. |
| `src/services/vaultIntegrityRuntimeService.ts` | `buildCrossDeviceRevalidationResult()` | Downgrade-Heuristik | **Entfernt** | Downgrade ist verboten. |
| `src/services/vaultIntegrityRuntimeService.ts` | V1-Pfade in `finalizeVaultUnlockIntegrity()` | V1-Fallback nach V2 | **Entfernt** | Kein Fallback auf alte Logik. |
| `src/services/vaultQuarantineRecoveryService.ts` | `restoreQuarantinedItemFromTrustedSnapshot()` | Direkter Upsert auf `vault_items` | **Entfernt** | Direkte alte Vault-Writes sind verboten. |
| `src/services/vaultQuarantineRecoveryService.ts` | `deleteQuarantinedItemFromVault()` | Direkter Delete auf `vault_items` | **Entfernt** | Direkte alte Vault-Writes sind verboten. |
| `src/services/vaultQuarantineRecoveryService.ts` | `buildTrustedItemUpsertPayload()` | Hilfsfunktion für direkten Write | **Entfernt** | Direkte alte Vault-Writes sind verboten. |
| `src/services/vaultQuarantineRecoveryService.ts` | `isVaultItemAbsentOnServer()` | Hilfsfunktion für alte Logik | **Entfernt** | Direkte alte Vault-Writes sind verboten. |
| `src/services/vaultQuarantineRecoveryService.ts` | `canAcceptMissing` in `QuarantineResolutionState` | Generisches Accept ohne signierte Operation | **Entfernt** | Accept muss über signierte Operation laufen. |
| `src/services/vaultOpLog/vaultOpLogFeatureFlags.ts` | `isVaultOpLogRepositoryEnabled()` | Feature-Flag für neues Modell | **Hardcodiert `true`** | Neues Modell ist nach Phase 11 Pflicht. |
| `src/services/vaultOpLog/vaultOpLogFeatureFlags.ts` | `isVaultOpLogShadowModeEnabled()` | Feature-Flag für Shadow Mode | **Hardcodiert `false`** | Shadow Mode darf keine alte Logik aktivieren. |
| `src/services/vaultOpLog/vaultOpLogFeatureFlags.ts` | `isVaultOpLogPhase9UIEnabled()` | Feature-Flag für Phase 9 UI | **Hardcodiert `true`** | Phase 9 UI ist nach Phase 11 Pflicht. |
| `src/contexts/vault/*` | Imports/Calls alter Funktionen | Alte Runtime-Logik in Context/Provider | **Entfernt** | Keine alte Logik in Context/Provider. |

## Legacy-Code, der im Migration-Service verbleibt

| Datei | Symbol | Grund |
|---|---|---|
| `src/services/legacyVaultRepairService.ts` | Verschiedene | Wird von `vaultUserKeyMigrationService.ts` importiert; darf nur im Migrationskontext laufen. |
| `src/services/legacyVaultMetadataMigrationService.ts` | Verschiedene | Wird von `vaultUserKeyMigrationService.ts` importiert; darf nur im Migrationskontext laufen. |

## Prüfliste nach Umsetzung

- [ ] `LOCAL_WRITE_CACHE_TTL_MS` existiert nicht mehr in Runtime.
- [ ] `canRebaselineTrustedMutation` existiert nicht mehr in Runtime.
- [ ] `canRebaselineRecentLocalMutation` existiert nicht mehr in Runtime.
- [ ] `snapshotDigest` wird nicht mehr als Runtime-Trust-Quelle verwendet.
- [ ] Kategoriefehler blockieren nicht mehr global den Vault.
- [ ] Keine direkten Runtime-Upserts/Deletes auf `vault_items`.
- [ ] Feature-Flags sind hardcodiert und reaktivieren keine alte Logik.
- [ ] Legacy-Code ist nur noch im Migration-Service.
