# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden hier dokumentiert.

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
