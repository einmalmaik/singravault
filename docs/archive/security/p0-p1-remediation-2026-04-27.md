# P0/P1 Remediation Notes - 2026-04-27

## REV-P0-1: Klartext-Vault-Export in Git-Historie

Code kann diese Kompromittierung nicht allein beheben. Das Entfernen der Datei
aus dem Arbeitsbaum reicht nicht aus, weil die Secrets in bestehenden Git-Objekten,
Remote-Refs, lokalen Klonen und möglichen CI-/Release-Artefakten weiter lesbar
bleiben.

Code-/Repo-Maßnahmen in diesem Stand:

- Der aktuelle Arbeitsbaum enthält keinen getrackten `src-tauri/singra-vault-export-*.json`.
- Lokale, ignorierte Safe-Mode-Exportdateien unter `src-tauri/` wurden entfernt.
- `.gitignore` blockiert Vault-Exportdateien, `.env` und Loadtest-Token-Dateien.
- `npm run security:repo-guard` blockiert getrackte und lokale Export-/Recovery-Artefakte.
- CI, Security-Workflow und Desktop-Release fuehren den Repo-Guard aus.
- Der bestehende Release-Artefakt-Check laeuft jetzt auch vor Desktop-Releases.
- Gitleaks bleibt im Security-Workflow aktiv.

Operative Incident-Response, manuell erforderlich:

- Alle exponierten Passwörter rotieren.
- Alle exponierten API-Keys und Tokens widerrufen und neu erzeugen.
- Betroffene TOTP-Seeds neu einrichten.
- Betroffene Sessions invalidieren.
- Git-Historie mit `git filter-repo` oder BFG bereinigen, sofern Repo/Remote das erlaubt.
- Remote-Refs, Tags, Forks, lokale Klone, CI-Caches, Build-Artefakte und Releases pruefen.
- Nach History-Rewrite alle Mitwirkenden über Re-Clone/Rebase-Anforderungen informieren.

## REV-P1-1: Destruktiver Vault-Reset

Der aktuelle Endzustand nutzt `reset_user_vault_state(UUID)` mit frischer JWT-Prüfung
und einer serverseitigen, kurzlebigen Einmal-Challenge. Die frühere No-Arg-Migration
ist in diesem Stand nicht mehr destruktiv und nicht an `authenticated` gegrantet,
damit neue Deployments keinen unsicheren Zwischenzustand erzeugen.

Verbleibende operative Einschränkung: Datenbanken, auf denen die alte Migration
bereits angewendet wurde, müssen die spätere gehärtete Migration angewendet haben.

## CRYPTO-P1-4: Public-Key-Authentizität

Im aktuellen Kerncode wurde kein belastbarer Empfänger-Key-Pinning-/Fingerprint-
oder Signaturmechanismus für Shared-/Emergency-/Family-Public-Keys nachgewiesen.
Das ist ein bestaetigtes Architektur-Risiko, aber kein sicherer Minimal-Patch:
eine halb eingefuehrte Signaturschicht koennte Shares sperren oder falsches
Vertrauen erzeugen.

Sichere nächste Maßnahme:

- Datenmodell für Public-Key-Fingerprints und Key-Versionen festlegen.
- Ersten gesehenen Empfänger-Key pinnen.
- Key-Wechsel beim Teilen blockieren oder mit expliziter Re-Verifikation erzwingen.
- UI für Fingerprint-/Out-of-band-Verifikation entwerfen.
- Migration für bestehende Empfänger-Keys mit klarer Legacy-Behandlung planen.

## CRYPTO-P1-5: Legacy-derived UserKeys

Der deterministische `migrateToUserKey`-Pfad ist für bestehende Daten absichtlich
lesekompatibel. Eine Rotation auf random UserKey würde eine vollständige,
atomare Neuverschlüsselung von Vault Items, Kategorien und Private Keys brauchen.
Das wurde in diesem Auftrag nicht umgesetzt, um keinen Datenverlust zu riskieren.

Backlog:

- Legacy-derived UserKeys im Profil markieren.
- Atomare Rotation auf random UserKey planen.
- Recovery-/Rollback-Verhalten definieren, bevor Nutzerdaten umgeschluesselt werden.
