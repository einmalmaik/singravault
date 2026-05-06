# Singra Vault Security Notes - Phase 12

Stand: 2026-05-06

## Sicherheitsinvarianten

- Serverdaten sind keine Wahrheit. Normaler Vault-Zustand entsteht nur aus lokal verifizierten Operationen vertrauenswürdiger Geräte.
- Records werden erst nach Operation-, Autor-, Signatur-, AAD- und CiphertextHash-Prüfung entschlüsselt.
- Migration ist ein separater Zustand und kein normaler Vault-Betrieb.
- Teilmigrationen blockieren normale UI und Datenabfluss.
- Legacy-Zeilen werden nicht destruktiv gelöscht und nach verifizierter Migration nicht als Runtime-Trust-Quelle genutzt.
- Alte Rebaseline-, TTL-, Snapshot-Digest- und Kategorie-Globalblockade-Logik bleibt deaktiviert.
- Runtime-Writes auf `vault_items` und `categories` bleiben verboten.
- Export und andere Data-Egress-Flows arbeiten im OpLog-Pfad verified-only. Eine Blocklist reicht nicht aus.
- Operationen anderer Geräte werden mit den Public Keys aus `vault_device_trust_records` geprüft, nicht mit dem aktuellen lokalen Device-Key.

## Migration-Sicherheitsmodell

Der Unlock-Finalizer prüft nach erfolgreicher Schlüsselableitung `evaluateVaultMigrationGate()`. Nur `notNeeded` und `verified` geben den normalen Vault frei. `required`, `ready`, `running`, `committed`, `failed` und `preflightFailed` halten den Vault gesperrt und zeigen den Migrationsstatus.

Der Start der Migration erfolgt nur über expliziten User Consent im Migrationspanel. Der Runtime-Orchestrator:

1. lädt Legacy-Zeilen read-only,
2. lädt oder erzeugt eine lokale Device-Signing-Identity,
3. verlangt einen nicht extrahierbaren lokalen Device-Signing-Key,
4. ruft `migrateVault()` auf,
5. lädt danach den Operation-Log-Zustand neu,
6. verifiziert ihn mit der State Machine,
7. erlaubt erst danach den normalen Unlock.

Normale Dual-Unlock-Ergebnisse laufen weiter über den primären Unlock-Pfad, damit der Migrationskontext den Vault-KDF-Output erhält. Der Duress-Pfad bleibt davon getrennt und öffnet keinen normalen Migrationszustand.

`migrateVault()` schreibt keinen Device-Trust-/Head-/Commit-Zustand vor Preflight und Pre-Migration-Snapshot. Nach erfolgreicher Verifikation wird ein nicht geheimer lokaler Completion-Marker geschrieben, damit verbleibende Legacy-Zeilen nicht erneut als inkonsistenter Teilzustand blockieren.

## Supabase/RPC-Evidenz

Supabase-local läuft in dieser Arbeitskopie auf alternativen Ports, damit das fremde lokale Projekt `ndrfhipyjwwhzsqhzkrs` auf `54322` nicht gestoppt oder gelöscht werden musste. Die Phase-2-RPC/RLS-Integrationstests wurden gegen die lokale Instanz ausgeführt.

Gefundene und behobene DB-Blocker:

- `bootstrap_vault_trust` verletzte die FK von `vault_device_trust_records.added_op_id`, weil der initiale Trust-Root vor der ersten Operation existiert. Der initiale Bootstrap darf nun `added_op_id = NULL` setzen; spätere Trust-Änderungen bleiben signierte Operationen.
- `get_vault_changes_since` lieferte `intent_id`/`rebased_from_op_id` nicht in der deklarierten Spaltenreihenfolge zurück.
- Zwei ältere lokale Migrationen waren unter Supabase-local nicht sauber ausführbar und wurden für lokale Bootstrap-Kompatibilität gehärtet, ohne Runtime-Trust-Regeln zu ändern.

## Data-Egress-Gates

Export, Suche, Clipboard und UI-Normalanzeige dürfen nur verified Records verwenden. Quarantined Records, Conflict Records und Records ohne verified-Status dürfen nicht als normale Items erscheinen. Passwort-Autofill bleibt gemäß Phase-10-Policy blockiert, wenn der verified-only Kontext nicht erfüllt ist.

Aktueller Status: Die zentralen OpLog-Data-Egress-Policies sind getestet. Die Exportpfade verwenden im OpLog-Kontext eine verified-Allowlist und entschlüsseln nicht-allowlistete Rows nicht. Vollständige echte Runtime-Evidenz, dass alle UI-Listen ausschließlich aus dem verified OpLog-State lesen, ist noch nicht abgeschlossen.

## Runtime-Writes

Direkte Runtime-Writes auf `vault_items` und `categories` bleiben verboten. Die aktuellen Item-/Kategorie-UI-Schreibaktionen sind blockiert, weil der produktive signierte CRUD-Service noch nicht vollständig existiert.

Eine Freigabe darf erst erfolgen, wenn Create/Update/Delete über Operation Builder, Pending Queue, `submit_vault_operation`, Reload und State-Machine-Verifikation laufen und ihre Base-Record-Metadaten aus verified OpLog-State beziehen. Der vorhandene UI-State enthält dafür aktuell noch nicht die nötigen verified Base-Metadaten für sichere Update-/Delete-CAS-Entscheidungen.

Restore/Delete/Resolve bleiben blockiert, solange kein vollständiger verifizierter Record-/Snapshot-Kontext an einen signierten Commit-Pfad gebunden ist. Keine generische Accept-Aktion ist erlaubt.

## Tests und Evidenz

Ausgeführt:

- `npx tsc --noEmit` - bestanden.
- `npm run build` - bestanden.
- `npx vitest run src/contexts` - 4 Dateien, 91 Tests bestanden.
- `npx vitest run src/services/vaultOpLog/__tests__` - 24 Dateien, 428 Tests bestanden.
- `npx vitest run src/components/vault` - 13 Dateien, 110 Tests bestanden; bestehende React-act/i18n-Warnungen.
- `npx vitest run src/test/security-hardening-contracts.test.ts` - 20 Tests bestanden.
- `npx vitest run src/test/vault-op-log-phase2-migration-contract.test.ts` - 50 Tests bestanden.
- `npx vitest run src/test/integration/vault-op-log-phase2-integration.test.ts` gegen Supabase-local - 12 Tests bestanden.

Runtime-Smoke:

- `/vault` im Browser geöffnet: Route rendert ohne Provider-/Hook-Crash und leitet erwartungsgemäß nach `/auth?redirect=%2Fvault`.
- `/vault/settings` im Browser geöffnet: Route rendert ohne Provider-/Hook-Crash und leitet erwartungsgemäß nach `/auth?redirect=%2Fvault%2Fsettings`.
- Console: erwarteter 401 vom Auth-Session-Endpunkt im ausgeloggten Zustand, plus nicht-blockierende Dev-/Autocomplete-Hinweise.

Nicht ausgeführt:

- Tauri-Runtime mit echten Testdaten.
- Vollständige Multi-Client-/Offline-/Online-E2E-Flows mit realen Clients.
- Produktive Item-/Kategorie-CRUD-E2E-Flows, weil diese Flows sicher blockiert bleiben.

## Restrisiken

- Kompromittierte vertrauenswürdige Geräte können legitime signierte Operationen erzeugen.
- Vollständige Serverlöschung bleibt ein Verfügbarkeitsproblem und braucht Recovery/Snapshot-Prozesse.
- Malware im entsperrten Client-Prozess kann Klartext lesen.
- Signierte Item-/Kategorie-CRUD-Flows sind noch nicht vollständig produktiv verdrahtet; betroffene UI-Aktionen bleiben blockiert.
- Restore/Delete/Resolve sind sicher blockiert, aber nicht produktiv nutzbar.
- Multi-Client-/Offline-Runtime-Evidenz fehlt noch.

## Nicht verifizierte Annahmen

- Persistenz nicht extrahierbarer `CryptoKey`-Handles ist in allen Ziel-Web-/Tauri-Laufzeiten verfügbar.
- Premium-Overlay nutzt die entfernten alten Integrity-ServiceHooks nicht produktiv; die Registrierung wurde entfernt, damit keine Legacy-Trust-API Build-Abhängigkeit bleibt.
- Der endgültige produktive OpLog-CRUD-Service kann ohne Legacy-Table-Fallback an die bestehende UI angebunden werden.
