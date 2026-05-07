# Singra Vault Security Notes - Phase 12

Stand: 2026-05-07

## Update 2026-05-08 - OpLog Device Identity nach Verified-Unlock

- Ursache fuer `OpLog-Device-Identitaet fehlt`: Der OpLog-CRUD-Kontext las die lokale Device-Metadaten-Identity nur aus `localStorage`. Nach Migration/verified konnte diese nicht-sensitive Metadata fehlen, obwohl der non-extractable Device-Signing-Key noch in IndexedDB und der zugehoerige Trusted-Device-Record in Supabase vorhanden waren.
- Reparatur: Der Runtime-Pfad erzeugt keine Dummy-Identity. Er rekonstruiert die Identity nur dann, wenn ein lokaler non-extractable Signing-Key fuer denselben User/Vault existiert und per Sign/Verify-Challenge gegen den Public Key eines `trusted` Cloud-Trust-Records passt.
- Wenn kein lokaler Signing-Key oder kein passender `trusted` Trust-Record vorhanden ist, bleibt OpLog-CRUD fail-closed blockiert. Es werden keine Secrets, Private Keys, Vault Keys, Plaintexts, Ciphertexts oder Signed Bodies geloggt.
- Betroffen und korrigiert: OpLog-CRUD-Kontext und OpLog-UI-State-Refresh. Dadurch koennen Item-, Kategorie- und TOTP/Authenticator-Record-Aenderungen dieselbe verifizierte Device-Identity verwenden.
- Verifiziert: gezielte Unit-Tests fuer Identity-Recovery positiv/negativ/revoked und bestehender Device-Store-Test.
- Folgefix: Nach `vaultMigrationStatus === "verified"` rendert `VaultItemList` Eintraege aus dem lokal verifizierten OpLog-State, nicht mehr aus dem Legacy-Snapshot. Dadurch bleiben verified-only Egress und State-Machine-Verifikation die Quelle der UI, waehrend alte Manifest-/Snapshot-Pruefungen im normalen Listenpfad inaktiv bleiben.
- Folgefix: OpLog-CRUD signiert neue Operationen mit dem `trust_epoch` des passenden `trusted` Device-Trust-Records. Ein hartkodierter Epoch-Wert wuerde ansonsten nach erfolgreichem Submit beim Reload als `unknownAuthor`/`device_trust_epoch_mismatch` quarantined werden. Die Commit-Verifikation meldet quarantined-after-reload jetzt mit bereinigter Ursache statt generisch `submitted_record_missing_after_reload`.
- Folgefix: Der Item-Dialog liest und bearbeitet Eintraege nach `verified` aus dem verifizierten OpLog-State statt aus dem Legacy-Snapshot. OpLog-Quarantaene-Records zeigen keine Restore/Delete-Aktionen mehr, solange kein verifizierter Tombstone-/Record-Kontext fuer eine signierte Operation vorhanden ist.

## Update 2026-05-07 - UI-CRUD/Quarantaene-Actions

- Item-CRUD ist produktiv an den OpLog-CRUD-Service angebunden: `VaultItemDialog` ruft `opLogCreateItem`, `opLogUpdateItem` und `opLogDeleteItem`.
- Kategorie-CRUD ist produktiv an den OpLog-CRUD-Service angebunden: `CategoryDialog` ruft `opLogCreateCategory`, `opLogUpdateCategory` und `opLogDeleteCategory`.
- UI-Erfolg wird erst nach Service-Erfolg angezeigt; der Service fuehrt Submit, Reload und State-Machine-Verifikation aus.
- OpLog-Quarantaene-/Konfliktpanels sind nicht mehr pauschal deaktiviert. Restore/Delete/Resolve werden ausgefuehrt, wenn verified Record-/Snapshot-Kontext vorhanden ist, und blockieren sonst fail-closed mit sichtbarer Fehlermeldung.
- Direkte UI-Schreibpfade auf `vault_items` und `categories` sind aus Item-/Kategorie-Dialogen entfernt.
- Weiterhin vorhanden sind Legacy-Lesebruecken in Settings-Export, Repair, Offline-Snapshot und Migration. Diese Pfade schreiben keine normalen UI-CRUD-Mutationen, bedeuten aber: Das alte Integritaets-/Quarantaene-System ist noch nicht rueckstandslos aus jedem Produktiv-Lesepfad entfernt.
- Nach dieser Aenderung verifiziert: `npx tsc --noEmit`, `npm run build`, `npm run lint` und eine gezielte Vitest-Suite mit 6 Dateien / 126 Tests.

## Update 2026-05-07 - Cloud-Supabase-Read-only-Check

- Projekt: `lcrtadxlojaucwapgzmy`.
- Umfang: Nur lesende Schema-/Metadata-/Count-Pruefung und unauthentifizierte Negativtests. Keine Cloud-Schreiboperationen, keine produktionsnahen Vault-Daten veraendert, keine Klartext-/Secret-Daten gelesen.
- Lokale und Cloud-Migrationsanzahl stimmen ueberein: 82 Migrationen; Cloud-Latest ist `20260505193000_vault_op_log_bootstrap_fk_fix`.
- Phase-2/Phase-12-Migrationen sind in Cloud-Migrationshistorie vorhanden: `20260504130000_vault_op_log_phase2_records_operations_trust`, `20260504130100_vault_op_log_phase2_rpcs`, `20260505193000_vault_op_log_bootstrap_fk_fix`.
- OpLog-Tabellen existieren mit aktivem RLS: `vault_records`, `vault_operations`, `vault_device_trust_records`, `vault_op_log_heads`.
- OpLog-RPCs existieren mit erwarteten Signaturen, `SECURITY DEFINER` und `search_path=public`: `submit_vault_operation`, `get_vault_head`, `get_vault_changes_since`, `get_vault_records_by_ids`, `bootstrap_vault_trust`.
- RPC-Definitionsmarker fuer CAS/Head-Felder sind vorhanden: `submit_vault_operation` referenziert `previous_ciphertext_hash`, `base_vault_head`, `resulting_vault_head`, `op_id`, `op_hash`, `intent_id`, `rebased_from_op_id`.
- Negativtests ohne Auth gegen `submit_vault_operation`, `bootstrap_vault_trust` und `get_vault_changes_since` schlagen mit `Not authenticated` fehl.
- Aktueller Cloud-Datenstand per Count-only: `vault_records` 0, `vault_operations` 0, `vault_device_trust_records` 2, `vault_op_log_heads` 2, Legacy `vault_items` 31, Legacy `categories` 3.
- Review-Punkt vor Release: Die OpLog-Tabellen und OpLog-RPCs haben `anon`-Grants. RLS und `auth.uid()`-Checks blockieren die getesteten unauthentifizierten RPC-Pfade, die unnoetigen `anon`-Grants sollten trotzdem entfernt oder in einer Migration explizit begruendet werden.
- Nicht verifiziert: Authentifizierte Cloud-E2E-Schreibtests, Web/Tauri-/Multi-Client-/Offline-Flows und echte OpLog-CRUD-Roundtrips gegen Cloud. Grund: Es lag kein isolierter Cloud-Testnutzer/Test-Vault mit ausdruecklicher Erlaubnis fuer Mutationen vor.

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
- UI-CRUD nach `verified` liest Item-Dialog, Item-Liste, Kategorie-Dialog und Kategorie-Sidebar aus `opLogLocalVaultState.recordsById`; Legacy-Snapshot-Decrypt bleibt auf nicht migrierte Legacy-Zustände begrenzt.
- Kategorie-Delete im UI bietet keine automatische Item-Löschung mehr an und bleibt bei referenzierenden Items blockiert.
- Folgefix: OpLog-CRUD signiert neue Operationen mit dem `trust_epoch` des passenden `trusted` Device-Trust-Records. Ein hartkodierter Epoch-Wert würde ansonsten nach erfolgreichem Submit beim Reload als `unknownAuthor`/`device_trust_epoch_mismatch` quarantined werden. Die Commit-Verifikation meldet quarantined-after-reload jetzt mit bereinigter Ursache statt generisch `submitted_record_missing_after_reload`.
- Folgefix Delete/Tombstone: Eine gültig signierte Delete-Operation wird als Löschbeweis behandelt, auch wenn der Server eine stale/mismatched `vault_records`-Zeile zurückliefert. Der stale Record wird dabei nicht entschlüsselt und nicht angezeigt; ungültige Signaturen oder unbekannte Autoren bleiben Quarantäne.

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
- Folgeprüfung Device-Identity/UI-CRUD:
  - `npx tsc --noEmit` - bestanden.
  - `npx vitest run src/components/vault/__tests__/VaultItemList.test.tsx src/components/vault/__tests__/VaultItemDialog.test.tsx src/services/vaultOpLog/__tests__/vaultOpLogDeviceIdentityRecovery.test.ts src/services/vaultOpLog/__tests__/vaultOpLogCrudService.test.ts src/contexts/__tests__/VaultContext.test.tsx --reporter=dot` - 5 Dateien, 114 Tests bestanden.
- Folgeprüfung Delete/Tombstone:
  - `npx tsc --noEmit` - bestanden.
  - `npx vitest run src/services/vaultOpLog/__tests__/vaultStateMachine.test.ts --reporter=dot` - 1 Datei, 16 Tests bestanden.

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
- UI-CRUD manuell prüfen: Item erstellen, bearbeiten, Kategorie erstellen, Kategorie zuweisen, Item löschen; keine neue `unknownAuthor`-/`device_trust_epoch_mismatch`-Quarantäne und keine alte Manifest-/Snapshot-Meldung.

## Restrisiken

- Kompromittierte vertrauenswürdige Geräte können weiterhin gültig signierte bösartige Operationen erzeugen.
- Persistenz nicht-extrahierbarer `CryptoKey`-Handles ist nicht in allen Ziel-Web-/Tauri-Laufzeiten bewiesen.
- Vollständige Serverlöschung bleibt ein Verfügbarkeitsproblem und braucht verifizierte Snapshot-/Recovery-Prozesse.
- Alte V2-/Integrity-Brücken sind noch im Unlock-/Verify-Pfad erreichbar; sie treffen keine alten Write-Entscheidungen, sind aber nicht der finale Phase-12-Zielzustand.
- Cloud-E2E mit isoliertem Testvault ist nach dem Device-Trust-Folgefix noch nicht durchgeführt; produktive Freigabe braucht diesen Runtime-Nachweis.

## Rollback-Risiken

- App-Rollback darf alte Trust-Logik, TTL-Trust, automatische Rebaseline oder Legacy-Snapshot-Digest nicht reaktivieren.
- App-Rollback darf neue `vault_records`, `vault_operations`, `vault_op_log_heads` oder Device-Trust-Records nicht löschen.
- Teilmigrationen (`ready`, `running`, `committed`, `failed`, `preflightFailed`) müssen blockiert bleiben und dürfen nicht als normaler Legacy-Vault angezeigt werden.
