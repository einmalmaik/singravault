# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden hier dokumentiert.

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
