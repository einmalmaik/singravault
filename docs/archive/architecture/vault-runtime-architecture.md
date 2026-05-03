# Vault Runtime Architecture

Stand: 2026-04-29

## Modulübersicht

| Thema | Datei | Aufgabe |
|---|---|---|
| React Gateway | `src/contexts/VaultContext.tsx` | Provider-State, Public API, Lifecycle, Delegation an Services |
| Runtime State | `src/services/authRuntimeState.ts`, `src/services/vaultSessionStateMachine.ts` | Account-, Vault-, Device-Key-, 2FA-, Quarantäne- und Integrity-Zustände typisieren |
| Unlock Gate | `src/services/vaultUnlockOrchestrator.ts` | Vault-2FA vor Key Release prüfen |
| Device-Key Unlock | `src/services/deviceKeyUnlockOrchestrator.ts` | Device-Key-required, Native Bridge und Browser/PWA-Key-Verfügbarkeit prüfen |
| Integrity Decision | `src/services/vaultIntegrityDecisionEngine.ts` | Canonicalization, Baseline-Inspection, Kategorie-Block, Trusted-Rebaseline-Policy |
| Quarantäne | `src/services/vaultQuarantineOrchestrator.ts` | Quarantäne-Summary, UI-Ergebnis, Decrypt-Guard |
| Error Mapping | `src/services/vaultErrorMapper.ts` | technische Fehler auf UI-sichere Codes abbilden |
| Account/Vault Policy | `src/services/accountVaultRoutePolicy.ts` | Account Settings von Vault-Zugriff trennen |
| Dev-Testaccount | `scripts/dev/ensure-dev-test-account.mjs`, `src/config/devTestAccountConfig.ts` | echter Dev-User serverseitig; Client nur UI-Flag |

## Wo neue Entwickler ändern

- Auth-/Vault-Zustände: `vaultSessionStateMachine.ts` und Tests.
- Vault-Unlock-Gates: `vaultUnlockOrchestrator.ts`.
- Device-Key-required: `deviceKeyUnlockOrchestrator.ts` und Device-Key-Policy-Tests.
- Quarantäne/Integrity: `vaultIntegrityDecisionEngine.ts` und `vaultQuarantineOrchestrator.ts`.
- UI-Fehlercodes: `vaultErrorMapper.ts`.
- Account Settings vs Vault Settings: `accountVaultRoutePolicy.ts`.
- React Provider API: nur `VaultContext.tsx`.

## State-Grenzen

Account-Login erzeugt keine Vault-Entschlüsselung. Vault-Unlock setzt den Runtime-Key nur nach erfolgreichem Master-/Passkey-/Device-Key-/2FA-/Integrity-Pfad. Lock löscht Vault-Plaintext und Key-State aus der Runtime, aber nicht die Account-Session. Logout löscht Account- und Vault-Runtime-State.

## Integrity-Entscheidungen

Die Decision Engine behandelt gleiche Snapshots deterministisch. Item-Drift wird als Quarantäne ausgegeben. Kategorie-Drift, unreadable Baseline, Legacy-Baseline-Mismatch und malformed Snapshot blockieren den Vault. Rebaseline ist nur bei explizit trusted lokaler Mutation oder erlaubter Erstbaseline möglich.

## Device Key

`device_key_required` ist ein Vault-Unlock-Schutz, kein Account-Login-Schutz. Ein neues Gerät darf sich am Account anmelden, muss aber für den Vault-Unlock den passenden Device Key importiert oder in der lokalen Keychain vorhanden haben. Der Server speichert nur nicht-sensitive Protection-Metadaten.

## Dev-Testaccount

Der Dev-Testaccount ist kein Auth-Bypass. `npm run dev` und `npm run tauri:dev` starten ein Node-Script, das bei gesetzter server-only Env einen echten Supabase-User anlegt oder aktualisiert. Der Client darf nur `VITE_DEV_TEST_ACCOUNT_UI` und optional eine nicht-sensitive E-Mail-Hilfe lesen.
