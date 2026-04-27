# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden hier dokumentiert.

## 0.4.0 - 2026-04-27

### Highlights

- Sicherheitsrelease mit bereinigter Git-Historie für den versehentlich committeden Klartext-Vault-Export
- OPAQUE-only Passwort-Authentifizierung, Reset- und Change-Flows wurden konsolidiert und gehärtet
- Vault-Recovery, Quarantäne, Integrity-Rebaseline und destruktive Reset-Pfade wurden gegen Datenverlust und schwache Reauthentifizierung gehärtet
- Post-Quantum-Kryptografie ist klarer auf Key-Wrapping-/Sharing-/Emergency-Flows ausgerichtet
- Desktop-Dateirechte und Release-Guardrails wurden enger gefasst

### Added

- Vault-Quarantäne- und Recovery-Oberflächen für Integritätsprobleme
- Trusted-Rebaseline-Flow für Vault-Integrity-Recovery
- Server-seitig abgesicherte Vault-Reset-Recovery-Challenge mit frischer Reauthentifizierung
- Konfigurierbare TOTP-Parameter und persistente TOTP-Speicherpfade
- Pending-Premium-Attachment-Flow und Dialog-Reset-Verhalten
- Repository-Secret-Guardrail für CI und Release-Builds
- Release-Artefakt-Guardrail gegen versehentliche Secret-/Export-Artefakte
- Tests für AAD-gebundene Shared-Key- und Hybrid/PQ-Key-Wrapping-Pfade

### Changed

- Neue Sharing-/Emergency-/Family-Keypairs verwenden standardmäßig Hybrid/PQ-Key-Wrapping statt still auf RSA-only zu fallen
- Shared-Key-Entschlüsselung ist im normalen Runtime-Pfad fail-closed und erlaubt Legacy-No-AAD-Fallback nur noch explizit für Migrationspfade
- Hybrid/PQ-Key-Wrapping verlangt Kontextbindung per AAD für sicherheitskritische Wrapped Keys
- Vault-Reset-RPCs erzwingen serverseitig Challenge-, Reauth- und 2FA/VaultFA-Schutz statt nur Client-seitiger Bestätigung
- Tauri-Capabilities erlauben keine breiten rekursiven Schreib-, Rename- oder Löschrechte mehr auf Nutzerordnern
- Vault-Notes bleiben in Payloads und Snapshots verschlüsselt
- Snapshot-Quelle wird bei Integrity-Checks explizit berücksichtigt
- Support-Widget erhält Host-Auth sauberer
- Landing- und Auth-Branding wurden mit neuen Bildassets und Cover-Verhalten überarbeitet
- Post-Quantum-Dokumentation beschreibt PQ als Key-Wrapping-Schicht, nicht als Primär-Vault-Verschlüsselung

### Fixed

- Vault-Unlock zeigt Fehler zuverlässiger an und Reset-Logik wurde entkoppelt
- Legacy-Device-Keys werden toleranter migriert; defekte Secrets führen nicht mehr unkontrolliert in Folgefehler
- Kategorie-Integrity-Flows wurden stabilisiert
- OTP-Sendefehler bei OPAQUE-Signup rollen sauber zurück
- Passkey-Status wird auch dann geladen, wenn eine WebAuthn-Probe fehlschlägt
- Account-Deletion-, Auth-Fehler- und OAuth-Flows wurden robuster
- Legacy-Desktop-Tokens werden konsequenter bereinigt
- Lokales Secret-Handling und Core-Unlock-Pfade wurden gehärtet

### Security

- Der versehentlich committede Klartext-Vault-Export wurde aus der Branch-Historie entfernt und der Branch neu auf `origin/main` basiert
- CI prüft jetzt auf Klartext-Vault-Exports, `.env`-Leaks, TOTP-Seeds, private Keys und andere Secret-Muster
- Release-Builds prüfen zusätzlich, dass keine blockierten Export-/Secret-Artefakte ausgeliefert werden
- Die alte unsichere destruktive Reset-RPC-Zwischenversion wurde durch einen nicht gegranteten Fail-Closed-Placeholder ersetzt
- SECURITY DEFINER-RPCs für Vault-Reset laufen mit engerem Suchpfad und serverseitigen Schutzbedingungen
- AAD-Kontextbindung verhindert Runtime-No-AAD-Fallbacks und Wrapped-Key-Kontextvertauschung in den gehärteten Pfaden

### Operational Notes

- Passwörter und TOTP-Seeds aus dem exponierten Vault-Export müssen operativ rotiert werden; der Code-Release kann diese externen Konten nicht automatisch absichern
- Bestehende lokale Klone, Forks, CI-Caches und Artefakte können alte Git-Objekte weiter enthalten und müssen bei Bedarf separat bereinigt werden
- OPAQUE-Server-Setup wurde nicht rotiert, weil im Export kein Projekt-OPAQUE-Secret nachgewiesen wurde

## 0.3.0 - 2026-04-21

### Added

- Premium-only Desktop-Downloads können jetzt über einen Erweiterungsslot in die gehostete Oberfläche eingebunden werden, ohne den öffentlichen Core aufzublähen

### Changed

- `0.3.0` ist die erste Version, die wir als stabil markieren
- deutsche UI-Texte in Einstellungen, Abo-Hinweisen und Rechtstexten wurden vereinheitlicht
- Release-Dokumentation und Versionsmetadaten wurden auf den stabilen Desktop- und Web-Stand angehoben

### Fixed

- Desktop-Sitzungen bleiben über App-Neustarts hinweg stabil erhalten
- manuell verwaltete Abos zeigen saubere Hinweise ohne fehlerhafte deutsche Zeichen
- Premium/Core-Grenzen bleiben im Core-only-Build und in der gehosteten Premium-Integration konsistent

## 0.2.3 Beta - 2026-04-21

### Added

- Desktop-Anmeldung bietet jetzt einen eingebauten Dialog für den manuellen Callback-Link statt eines Browser-Prompts

### Changed

- manueller Social-Login-Fallback ist jetzt direkt in die Auth-Oberfläche integriert und passt zum restlichen App-Design

### Fixed

- Tauri leitet OAuth-Callbacks bei bereits laufender App jetzt sauber an die bestehende Instanz weiter
- nativer PKCE-Speicher unterstützt jetzt mehrere Schlüssel parallel, damit Desktop-Social-Login nicht an kollidierenden Flow-Zuständen scheitert

## 0.2.2 Beta - 2026-04-21

### Fixed

- Tauri-Desktop-Build injiziert keine PWA-Service-Worker-Registrierung mehr in `index.html`
- Windows-Desktop-Build bereinigt alte WebView-Service-Worker-Caches vor dem Start, damit offizielle Releases nicht an einer veralteten App-Shell hängen bleiben
- Tauri-Laufzeiterkennung berücksichtigt jetzt auch `tauri.localhost`, `asset.localhost` und `ipc.localhost`, damit Desktop-spezifische Pfade zuverlässig greifen

## 0.2.1 Beta - 2026-04-21

### Added

- offizieller Desktop-Release-Build prüft jetzt die gehostete Singra-Supabase-Konfiguration vor dem Tag-Build
- Windows-Installer-Ressourcen für NSIS und WiX mit eigenem Branding und Lizenzseite

### Changed

- öffentliche Desktop-Releases injizieren die offizielle Singra-Cloud-Konfiguration nur noch im GitHub-Action-Build
- Windows-Installer bindet den WebView2-Bootstrapper ein, damit Erstinstallationen robuster funktionieren
- Release-Notizen für Desktop-Tags wurden auf nutzerrelevante Hinweise reduziert

## 0.2.0 Beta - 2026-04-21

### Added

- Tauri-v2-Desktop-App auf Basis des bestehenden React/Vite-Bundles
- persistente Desktop-Anmeldung mit Keychain-gestütztem Refresh-Token-Speicher
- Deep-Link-basierter Social-Login für Desktop
- Update-Overlay für Desktop-Starts und eine Dev-Vorschau für den Updater-Screen
- Core-only-Start- und Build-Skripte für lokale Entwicklung und Self-Hosting
- GitHub-Actions-Workflows für Core-CI und signierte Desktop-Releases

### Changed

- zentrales Premium/Core-Boundary: öffentliches Repo bleibt buildbar ohne privates Paket
- Einstellungen, Navigation und Desktop-Pfade wurden auf gemeinsame Shell-Logik umgestellt
- deutsche Updater-Texte und Release-Hinweise wurden vereinheitlicht
- Dokumentation für Self-Hosting, Premium-Ladung und Desktop-Releases aktualisiert

### Fixed

- Social-Login-Weiterleitung zwischen Browser und Tauri-App
- mehrere Premium/Core-Auflösungsfehler im Desktop- und Settings-Bereich
- Update-Overlay-Rendering im Detailbereich

### Notes

- Diese Version ist weiterhin **Beta**.
- Das öffentliche Repository enthält nur den Core. Premium wird ausschließlich während privater Builds injiziert.
