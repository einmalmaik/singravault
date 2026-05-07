# Singra Vault Security Notes - Phase 12

Stand: 2026-05-07

## Ergebnis

Status: teilweise abgeschlossen, nicht releasefähig.

Umgesetzt und verifiziert sind der zentrale OpLog-CRUD-Service auf Service-Ebene, signierte Tombstone-Deletes, OpLog-Head-Chain-Verifikation beim UI-Reload, die Entfernung der alten Quarantäne-Write-Actions und verified-only Egress-Tests. Nicht vollständig abgeschlossen ist die produktive UI-Anbindung für Item-/Kategorie-CRUD sowie Restore/Delete/Resolve mit vollständigem verifiziertem Record-/Snapshot-Kontext.

## Sicherheitsinvarianten

- Serverdaten sind keine Wahrheit. Runtime-Records werden erst nach lokaler Operation-, Autor-, Signatur-, Head-, AAD- und CiphertextHash-Prüfung entschlüsselt.
- Quarantäne-, Conflict-, Unknown-Author-, Invalid-Signature-, AAD-Mismatch- und CiphertextHash-Mismatch-Records dürfen nicht entschlüsselt oder normal exportiert/gesucht/kopiert werden.
- Delete ist eine signierte Tombstone-Operation mit Record-Payload, keine direkte DB-Löschung.
- Restore ist nur mit vollständigem verifiziertem Snapshot-/Record-Kontext zulässig; der aktuelle UI-Action-Pfad blockiert fail-closed.
- Resolve erfindet keinen neuen Op-Type. Der Service modelliert Resolve als signierte Update-Operation.
- Kategorie-Delete löscht niemals automatisch Items; der Service blockiert bei referenzierenden Items.
- Keine automatische Rebaseline, kein TTL-Trust, kein Recent-Local-Mutation-Trust, keine Kategorie-Globalblockade als OpLog-Ersatz.
- Direkte Runtime-Writes auf `vault_items` und `categories` bleiben in UI/Import blockiert, bis die UI sichere OpLog-Base-Metadaten besitzt.

## Implementierter Stand

- `vaultOpLogCrudService.ts` orchestriert Operation Builder, Pending Queue, `submit_vault_operation`, Reload und State-Machine-Verifikation.
- Create/Update/Delete für Item- und Kategorie-Records sind im Service implementiert und getestet.
- Delete sendet jetzt eine signierte Tombstone-Payload; SQL/RPC aktualisiert den Record als Tombstone statt alte Ciphertext-Spalten unverändert zu lassen.
- `vaultOpLogUiOrchestrator.ts` verifiziert die globale Head-Chain vor Record-Egress und verarbeitet danach nur den letzten verifizierten Record-Zustand pro Record.
- Alte UI-Actions `restoreQuarantinedItem`, `deleteQuarantinedItem`, `acceptMissingQuarantinedItem` sind aus Context/Komponenten entfernt.
- `VaultQuarantineActions` nutzt nur noch `opLogRestoreRecord`/`opLogDeleteUntrustedRecord`; beide blockieren ohne Base-/Snapshot-Kontext typisiert.
- Export-Flows in `DataSettings` und `AccountSettings` blockieren fail-closed, wenn keine verifizierte OpLog-Allowlist verfügbar ist.

## Verifizierte Tests

- `npx tsc --noEmit` - bestanden.
- `npm run build` - bestanden.
- `npm run lint` - bestanden mit 7 bestehenden Warnungen.
- `npm audit --omit=dev` - bestanden, 0 Vulnerabilities.
- Runtime-Smoke per Playwright-Fallback:
  - `/vault/settings` geöffnet und erwartungsgemäß nach `/auth?redirect=%2Fvault%2Fsettings` geleitet.
  - `/vault` geöffnet und erwartungsgemäß nach `/auth?redirect=%2Fvault` geleitet.
  - Keine Provider-/Hook-/Context-Crashes; Konsole enthielt den erwarteten 401 im ausgeloggten Zustand sowie Dev-/Autocomplete-Hinweise.
- Ziel-Suite: 11 Dateien, 290 Tests bestanden:
  - `vaultOpLogCrudService.test.ts`
  - `vaultOpLogOperationBuilder.test.ts`
  - `vaultDataEgressPolicy.test.ts`
  - `vaultStateMachine.test.ts`
  - `vaultOpLogUiOrchestrator.test.ts`
  - `vault-op-log-phase2-migration-contract.test.ts`
  - `VaultQuarantineActions.test.tsx`
  - `VaultItemList.test.tsx`
  - `VaultContext.test.tsx`
  - `vaultQuarantineRecoveryService.test.ts`
  - `vaultRecoveryOrchestrator.test.ts`
  - `security-hardening-contracts.test.ts`
- Nach der Export-Egress-Verschärfung erneut ausgeführt: 6 Dateien, 220 Tests bestanden:
  - `vaultOpLogCrudService.test.ts`
  - `vaultDataEgressPolicy.test.ts`
  - `VaultQuarantineActions.test.tsx`
  - `VaultItemList.test.tsx`
  - `VaultContext.test.tsx`
  - `security-hardening-contracts.test.ts`
- Zusätzlicher Export-Egress-Contract: `security-hardening-contracts.test.ts` mit 21 Tests bestanden.

## Nicht bestanden / Nicht verifiziert

- `npm run test -- --reporter=dot` wurde nach 364 Sekunden durch Timeout beendet. Nicht als bestanden gewertet.
- `npx tsc -p tsconfig.app.json --noEmit --pretty false` wurde in diesem Lauf nicht separat ausgeführt; `npx tsc --noEmit` war erfolgreich.
- Supabase-local/RPC-Integration wurde in diesem Lauf nicht gestartet und nicht erneut gegen eine echte lokale DB ausgeführt.
- Web/Tauri/Multi-Client/Offline/Reconnect-E2E wurde in diesem Lauf nicht ausgeführt.
- In-App-Browser-Smoke war nicht ausführbar, weil `node_repl` Node >= 22.22.0 verlangt, lokal aber Node 22.16.0 auflöst; Runtime-Smoke erfolgte deshalb per Playwright-Fallback.

## Manueller Testplan

- Supabase lokal starten und Migrationen vollständig anwenden: `supabase start`, danach Phase-2/Phase-12-RPC-Integrationstests ausführen.
- Zwei Browserprofile oder zwei Clients mit getrennten Device-Signing-Keys verwenden:
  - Web erstellt Item, Tauri/zweiter Client lädt ohne Quarantäne.
  - Kategorie-Änderung auf Client A blockiert Client B nicht global.
  - Offline-Konflikt desselben Items erzeugt Conflict, nicht Quarantäne.
  - Server-Ciphertext-Manipulation führt zu Quarantäne ohne Decrypt.
  - Server-Delete ohne Delete-Operation führt zu Missing-Without-Delete und Recovery-Option nur aus verifiziertem Snapshot.
- Tauri mit persistiertem nicht-extrahierbarem `CryptoKey`-Handle testen.
- UI-CRUD erst freigeben, wenn Create/Update/Delete die Base-Metadaten aus verified OpLog-State beziehen und UI-Erfolg erst nach Reload/Verify angezeigt wird.

## Restrisiken

- Kompromittierte vertrauenswürdige Geräte können weiterhin gültig signierte bösartige Operationen erzeugen.
- Persistenz nicht-extrahierbarer `CryptoKey`-Handles ist nicht in allen Ziel-Web-/Tauri-Laufzeiten bewiesen.
- Vollständige Serverlöschung bleibt ein Verfügbarkeitsproblem und braucht verifizierte Snapshot-/Recovery-Prozesse.
- Alte V2-/Integrity-Brücken sind noch im Unlock-/Verify-Pfad erreichbar; sie treffen keine alten Write-Entscheidungen, sind aber nicht der finale Phase-12-Zielzustand.
- UI-CRUD und Import bleiben blockiert; produktive Schreibbarkeit ist deshalb noch nicht releasefähig.

## Rollback-Risiken

- App-Rollback darf alte Trust-Logik, TTL-Trust, automatische Rebaseline oder Legacy-Snapshot-Digest nicht reaktivieren.
- App-Rollback darf neue `vault_records`, `vault_operations`, `vault_op_log_heads` oder Device-Trust-Records nicht löschen.
- Teilmigrationen (`ready`, `running`, `committed`, `failed`, `preflightFailed`) müssen blockiert bleiben und dürfen nicht als normaler Legacy-Vault angezeigt werden.
