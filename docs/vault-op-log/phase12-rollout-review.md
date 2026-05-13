# Phase 12 Rollout Review

Stand: 2026-05-05

## Ergebnis

Phase 12 ist weitergeführt, aber noch nicht releasefähig abgeschlossen.

Erledigt sind Build-/Context-Stabilität, Consent-gated Migration, Supabase-local-Start auf konfliktfreien Ports, reale RPC/RLS-Integrationstests und die harte Blockierung unsicherer Legacy-Writes. Release-Blocker bleiben produktive signierte Item-/Kategorie-CRUD-Flows, produktive Restore/Delete/Resolve-Flows und vollständige Web-/Tauri-/Multi-Client-/Offline-E2E-Verifikation mit Testdaten.

## Geänderte Bereiche

- Supabase-local: `supabase/config.toml` nutzt alternative lokale Ports, damit das fremde Projekt `ndrfhipyjwwhzsqhzkrs` auf `54322` nicht angefasst werden musste.
- Supabase-Migrationen: lokale Bootstrap-Kompatibilität für alte Migrationen gehärtet; Phase-2 OpLog-RPCs um Bootstrap-FK-Fix und `get_vault_changes_since`-Spaltenreihenfolge korrigiert.
- RPC/RLS-Integrationstest: echte signierte Create-Operation, idempotenter Retry und `op_id`/`op_hash`-Missbrauch werden gegen Supabase-local geprüft.
- Vorheriger Phase-12-Stand bleibt erhalten: Migration-Gate, User-Consent-Start, Completion-Marker, Device-Signing-Key-Store, MigrationRequired-Panel und blockierte Legacy-Writes.

## Migrationsstatus-Verhalten

- `notNeeded`: normaler Unlock erlaubt.
- `verified`: normaler Unlock erlaubt.
- `required`: Vault bleibt locked; Panel bietet expliziten Start.
- `ready`: Vault bleibt locked; Panel bietet Start/Fortsetzen.
- `running`: Vault bleibt locked; Panel bietet Fortsetzen über Checkpoint.
- `committed`: Vault bleibt locked; Fortsetzen muss Reload + State-Machine-Verifikation durchführen.
- `failed`: Vault bleibt locked; Retry bleibt möglich, kein normaler Vault.
- `preflightFailed`: Vault bleibt locked; Retry/Support, kein normaler Vault.

## Item-/Kategorie-CRUD-Status

Die Operation Builder können signierte `create`, `update`, `delete` und `restore` Operationen bauen. Gegen Supabase-local wurde bewiesen, dass eine signierte Create-Operation über `submit_vault_operation` atomar Operation und Record schreibt und idempotent erneut angenommen wird.

Produktive UI-CRUD-Flows bleiben trotzdem blockiert. Der fehlende Teil ist ein zentraler Runtime-Write-Service mit verified OpLog-State als Schreibbasis:

- verified Base-Record-Metadaten inklusive `recordVersion`, `ciphertextHash`, `baseVaultHead`,
- lokale Device-Signing-Key-Verfügbarkeit,
- Pending Queue,
- `submit_vault_operation`,
- Reload,
- State-Machine-Verifikation,
- ehrlicher UI-Erfolg erst nach verifiziertem Commit oder sauberem Pending-State.

Der aktuelle UI-State projiziert für normale Anzeige noch nicht die vollständigen verified Base-Metadaten, die Update/Delete sicher brauchen. Ein Anschluss an Legacy-Snapshot-State wäre ein Rückfall in alte Trust-Logik. Deshalb bleiben Item Create/Update/Delete und Kategorie Create/Update/Delete sicher blockiert und sind Release-Blocker.

## Restore/Delete/Resolve-Status

`opLogRestoreRecord`, `opLogDeleteUntrustedRecord` und `opLogResolveConflict` geben weiterhin typisierte Blocker-Fehler zurück. Es gibt keine generische Accept-Aktion und keinen direkten Legacy-Repair-Write. Restore/Delete/Resolve dürfen erst aktiviert werden, wenn ein vollständiger verifizierter Record-/Snapshot-Kontext an einen signierten OpLog-Commit-Pfad angebunden ist.

## Supabase-local / RPC / RLS

Supabase-local läuft auf alternativen Ports:

- API/REST: `http://127.0.0.1:54331`
- DB: `127.0.0.1:54332`
- Studio: `http://127.0.0.1:54333`
- Mailpit: `http://127.0.0.1:54334`

Das fremde Projekt `ndrfhipyjwwhzsqhzkrs` belegt weiterhin `54322`; es wurde nicht gestoppt und nicht gelöscht.

Ausgeführt und bestanden:

- direkte `vault_records` Inserts/Updates/Deletes sind blockiert,
- `bootstrap_vault_trust` erstellt initialen Trust-Root und Head,
- wiederholter Bootstrap wird abgelehnt,
- unauthentifizierter `submit_vault_operation`-Aufruf wird abgelehnt,
- fremde Vault-ID wird abgelehnt,
- signierte Create-Operation schreibt Operation und Record atomar,
- identischer Retry derselben Operation ist idempotent,
- gleicher `op_id` mit anderem `op_hash` wird abgelehnt,
- `get_vault_changes_since` liefert sicherheitsrelevante Felder.

## Runtime-Smoke

- `/vault` geöffnet: Route rendert ohne Provider-/Hook-Crash und leitet im ausgeloggten Zustand nach `/auth?redirect=%2Fvault`.
- `/vault/settings` geöffnet: Route rendert ohne Provider-/Hook-Crash und leitet im ausgeloggten Zustand nach `/auth?redirect=%2Fvault%2Fsettings`.
- Console: erwarteter 401 vom Auth-Session-Endpunkt im ausgeloggten Zustand; keine Provider-/Hook-/Invalid-Hook-Fehler beobachtet.

Nicht ausgeführt:

- Tauri mit Testdaten.
- echte Multi-Client-/Offline-/Online-Flows.
- produktive Item-/Kategorie-CRUD-E2E-Flows, weil diese sicher blockiert bleiben.

## Antworten auf Pflichtfragen

- Wird Migration jetzt aufgerufen? Ja, über `startVaultMigration()`/`retryVaultMigration()` nach explizitem User Consent im Migrationspanel.
- Wann wird sie aufgerufen? Nach erfolgreichem Unlock-Versuch, wenn der Migration-Gate den normalen Unlock blockiert und der Nutzer im Panel startet.
- Kann sie vor Preflight und Snapshot echte serverseitige Daten verändern? Nein, `migrateVault()` schreibt Trust/Head/Commit erst nach Preflight und Pre-Migration-Snapshot.
- Was passiert bei Abbruch bei 50%? Checkpoint `running`/`committed` blockiert normalen Unlock; Retry/Resume nutzt den Checkpoint.
- Wird nach Migration neu geladen und verifiziert? Ja, der Runtime-Orchestrator ruft `loadVaultOpLogUiState()` auf und blockiert bei Fehler oder `lockedCritical`.
- Wird Legacy erst nach Verifikation als migriert markiert? Ja, `migrateVault()` markiert erst nach Verify; danach wird ein lokaler Completion-Marker geschrieben.
- Gibt es direkte Runtime-Writes auf `vault_items`/`categories`? In den geprüften UI-/Runtime-Schreibpfaden bleiben sie blockiert. Legacy-Reads zur Migration/Anzeige existieren weiter.
- Gibt es Feature-Flags, die alte Logik reaktivieren? In den ausgeführten OpLog-Feature-Flag-Tests nein.
- Ist das System ohne Feature-Flag produktionsreif? Noch nicht; produktive CRUD-Flows und vollständige Runtime-E2E-Evidenz fehlen.
- Gibt es einen Rollback-Plan ohne Rebaseline-/Legacy-Rückfall? Ja, siehe `docs/ROLLBACK_PLAN.md`.

## Testresultate

- `npx tsc --noEmit`: bestanden.
- `npm run build`: bestanden.
- `npx vitest run src/contexts`: bestanden, 4 Dateien, 91 Tests.
- `npx vitest run src/services/vaultOpLog/__tests__`: bestanden, 24 Dateien, 428 Tests.
- `npx vitest run src/components/vault`: bestanden, 13 Dateien, 110 Tests, mit bestehenden React-act/i18n-Warnungen.
- `npx vitest run src/test/security-hardening-contracts.test.ts`: bestanden, 20 Tests.
- `npx vitest run src/test/vault-op-log-phase2-migration-contract.test.ts`: bestanden, 50 Tests.
- `npx vitest run src/test/integration/vault-op-log-phase2-integration.test.ts`: bestanden, 12 Tests gegen Supabase-local.

## Restblocker

1. Signierte Item-Create/Update/Delete-Flows produktiv anbinden, ohne Legacy-Snapshot-State als Trust-Basis.
2. Signierte Kategorie-Create/Update/Delete-Flows produktiv anbinden; Kategorie-Delete braucht eine sichere Regel für referenzierende Items.
3. Restore/Delete/Resolve nur mit vollständigem signiertem Record-/Snapshot-Kontext aktivieren; aktuell sicher blockiert.
4. Tauri-/Multi-Client-/Offline-/Online-E2E-Flows mit Testdaten ausführen.

Phase 12 ist damit code-seitig deutlich weiter, aber weiterhin nicht releasefähig abgeschlossen.
