# Vault Runtime Refactor Map

Stand: 2026-04-29

Diese Map beschreibt, welche Verantwortlichkeiten aus `src/contexts/VaultContext.tsx` herausgezogen wurden und welche bewusst im React Context bleiben. Ziel ist Refactor ohne Public-API-Bruch.

## Klassifizierung

| Bereich | Vorher in VaultContext | Ziel/Status | Owner |
|---|---|---|---|
| React Provider und Hook | Context-Erzeugung, Provider-State, `useVault` | bleibt im Context | `src/contexts/VaultContext.tsx` |
| Session-Marker | direkte `sessionStorage` Writes/Deletes | ausgelagert | `src/services/vaultRuntimeFacade.ts` |
| Account/Vault Runtime-State | implizite Kombination aus Auth- und Vault-State | zentral typisiert | `src/services/authRuntimeState.ts`, `src/services/vaultSessionStateMachine.ts` |
| UI-sichere Fehlercodes | verstreute String-Erkennung | zentraler Mapper | `src/services/vaultErrorMapper.ts` |
| Device-Key-Unlock-Vorbedingungen | Context prüfte Local Secret Store, Bridge, Missing-Key | ausgelagert | `src/services/deviceKeyUnlockOrchestrator.ts` |
| Vault-2FA-Gate | Context lud Online-/Offline-2FA-Status | ausgelagert | `src/services/vaultUnlockOrchestrator.ts` |
| Integrity Snapshot Canonicalization | Context baute Snapshot selbst | ausgelagert | `src/services/vaultIntegrityDecisionEngine.ts` |
| Kategorie-Decryptability | Context entschied Kategorie-Block | ausgelagert | `src/services/vaultIntegrityDecisionEngine.ts` |
| Trusted Rebaseline Policy | Context entschied Drift-Scope | ausgelagert | `src/services/vaultIntegrityDecisionEngine.ts` |
| Quarantäne-Anzeige/Decrypt-Guard | Context mischte Runtime- und Baseline-Quarantäne | ausgelagert | `src/services/vaultQuarantineOrchestrator.ts` |
| Account Settings vs Vault Settings | implizit in Routen/Komponenten | zentrale Policy | `src/services/accountVaultRoutePolicy.ts` |
| Dev-Testaccount Client-Konfig | alte Testmode-Datei las UI-Flag direkt | client-sichere Config | `src/config/devTestAccountConfig.ts` |
| Master-Passwort-Setup | große UI-nahe Orchestrierung mit Supabase-Writes | bleibt vorerst im Context | späterer Data-Access-Split |
| Legacy-KDF-Reparatur | lange Bestandsdaten-Reparatur im Unlock | bleibt vorerst im Context | späterer Legacy-Migration-Service |
| Device-Key-Aktivierung/Rewrap | langer Aktivierungsflow mit Server-Writes | bleibt teilweise im Context | späterer Activation-Service |

## Sicherheitsinvarianten

- `device_key_required` darf Vault-Unlock ohne passenden lokalen Device Key nicht erlauben.
- Device-Key-Missing ist kein 2FA-Fehler.
- Vault-2FA ist ein Vault-Unlock-Gate, nicht Account-Login-2FA.
- Kategorie-Drift blockiert den Vault.
- Item-Drift quarantined nur betroffene Items.
- Untrusted Drift darf nicht automatisch rebaselined werden.
- Quarantined Items werden nicht entschlüsselt.
- Safe Mode darf nur trusted lokale Snapshots verwenden.
- URL-, localStorage- oder Mock-Auth-Bypässe sind verboten.
- Client-Code liest keine server-only Dev-Testaccount-Secrets.

## Move-/Keep-Entscheidungen

`VaultContext` bleibt Gateway/Fassade. Er darf React State setzen, Lifecycle koordinieren und bestehende Provider-Callbacks anbieten. Er darf keine neuen Integrity-, Device-Key-, 2FA- oder Route-Policies enthalten.

Nicht vollständig extrahiert sind Legacy-KDF-Reparatur, Setup und Device-Key-Aktivierung. Diese Pfade enthalten viele Supabase-Writes und Bestandsdaten-Migrationen. Sie bleiben im Context, bis separate Data-Access-Services mit Characterization-Tests existieren. Der aktuelle Refactor zieht trotzdem die sicherheitskritischen Entscheidungen aus diesen Pfaden heraus.
