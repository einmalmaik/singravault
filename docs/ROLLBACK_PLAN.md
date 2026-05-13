# Singra Vault Phase 12 Rollback Plan

Stand: 2026-05-05

Dieser Plan beschreibt ein operatives Release-Rollback für den Operation-Log-/Record-Integrity-/State-Machine-Pfad. Er ist kein Migration-Undo-Service und darf keine alte Rebaseline-, TTL-, Snapshot-Digest- oder Legacy-Runtime-Trust-Logik reaktivieren.

## Grundregeln

- Neue Operation-Log-Daten werden nicht gelöscht, um ein App-Rollback zu erzwingen.
- Legacy-Zeilen bleiben während der Migration nicht-destruktiv erhalten, sind aber nach verifizierter Migration keine normale Runtime-Trust-Quelle.
- Teilmigrationen bleiben blockierende Migrationszustände. Sie dürfen nicht als normaler verified Vault angezeigt werden.
- Rollback bedeutet höchstens: betroffene App-Version zurückziehen, neue Writes in Safe Mode/Read-only blockieren, Support-Recovery über signierte Operationen fortsetzen.
- Keine automatische Rebaseline.

## Migration-State-Matrix

| Status | Runtime-Verhalten | Rollback-/Recovery-Verhalten |
| --- | --- | --- |
| `notNeeded` | Normaler OpLog-Pfad darf öffnen. | App-Version kann zurückgerollt werden, solange keine alte Trust-Logik aktiviert wird. |
| `required` | Normaler Unlock bleibt blockiert; Consent-Panel wird angezeigt. | Keine Datenänderung erfolgt. Nutzer kann mit neuer Version erneut starten. |
| `ready` | Preflight/Checkpoint existiert, normale Vault-UI bleibt blockiert. | Erneut starten/fortsetzen; kein Legacy-Normalbetrieb. |
| `running` | Teilmigration blockiert normale Vault-UI. | Fortsetzen über Checkpoint; keine frische Migration ohne Checkpoint-Prüfung. |
| `committed` | Operationen sind geschrieben, aber Reload/Verify noch nicht terminal. | Support/Client muss Operation-Log neu laden und mit der State Machine verifizieren. Keine Legacy-Freigabe. |
| `verified` | Completion-Marker erlaubt normalen Unlock, auch wenn Legacy-Zeilen noch vorhanden sind. | App-Rollback darf neue OpLog-Daten nicht löschen. Legacy bleibt Recovery-Artefakt, nicht Wahrheit. |
| `failed` | Vault bleibt blockiert; Retry/Support erforderlich. | Retry aus Checkpoint, oder Support-Recovery. Keine direkte Tabellenreparatur. |
| `preflightFailed` | Vault bleibt blockiert. | Umgebung/Signals/RPC prüfen; kein Fallback auf Legacy-Trust. |

## Nicht rückwärtskompatible Zustände

- Ein Vault mit verifizierten Operation-Log-Records ist nicht mehr sicher über alte `vault_items`-/`categories`-Runtime-Writes zu betreiben.
- Ein `committed` Checkpoint ist nicht mit einer alten App-Version kompatibel, die keine Reload-/Verify-Phase kennt.
- Ein lokaler Completion-Marker ist nur ein nicht geheimes Freigabesignal für den neuen Gate; er ersetzt nicht die State-Machine-Verifikation.

## Release-Rollback

1. Neue App-Version zurückziehen oder Schreibzugriffe serverseitig in Safe Mode/Read-only stoppen.
2. Keine Datenbank-Deletes auf `vault_records`, `vault_operations` oder Device-Trust-Records ausführen.
3. Vaults mit `running`, `committed`, `failed` oder `preflightFailed` als Support-Fälle behandeln.
4. Für `committed`: neue App-Version oder Support-Tool muss Operation-Log neu laden und mit der State Machine verifizieren.
5. Für `verified`: normale Nutzung nur mit dem neuen OpLog-Pfad; alte Legacy-Trust-Modelle bleiben aus.

## Supabase-local-Rollback-Hinweis

Dieses Repo nutzt lokal alternative Ports (`54331` bis `54334`), damit das fremde Projekt `ndrfhipyjwwhzsqhzkrs` auf `54322` nicht gestoppt oder gelöscht werden musste. Das ist eine lokale Entwicklungsentscheidung und kein Produktions-Rollback-Mechanismus.

## Aktueller Phase-12-Status

- Migration ist per explizitem User Consent aus dem blockierten Unlock-Zustand startbar.
- `src/contexts` Tests sind auf Phase-11/12-Semantik aktualisiert und grün.
- Supabase-local startet auf alternativen Ports; RPC/RLS-Integrationstests laufen.
- Signierte Item-/Kategorie-CRUD-Flows sind noch nicht vollständig produktiv angebunden; unsichere Legacy-Writes bleiben blockiert.
- Restore/Delete/Resolve sind weiterhin blockiert, wenn kein vollständiger signierter Kontext existiert.
- Phase 12 ist deshalb weiterhin nicht releasefähig abgeschlossen.
