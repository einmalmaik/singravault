# Desktop Release Process

## Zielbild

- Das öffentliche Repository bleibt **Core-only**.
- Das private Premium-Repo wird nur während privater Builds separat ausgecheckt.
- Die GitHub-Release-Artefakte dürfen Premium enthalten.
- Die öffentlichen GitHub-Source-Archive bleiben trotzdem Core-only, weil sie nur den Commit-Inhalt des öffentlichen Repos enthalten.

## Wichtige Trennung

### Öffentlich

- Quellcode im Repository
- Self-Hosting ohne Premium
- Core-Webbuild
- Core-Tauri-Build

### Privat

- `@singra/premium`
- Build-Zugriff auf das Premium-Repo
- Signierschlüssel für Desktop-Updates
- serverseitige Premium-Freischaltung

## Benötigte GitHub-Secrets

- `TAURI_SIGNING_PRIVATE_KEY`
  - Inhalt des privaten Updater-Schlüssels
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
  - nur falls der Schlüssel passwortgeschützt ist
- `SINGRA_PREMIUM_PAT`
  - GitHub Personal Access Token mit Lesezugriff auf `einmalmaik/singra-premium`

## Optionale GitHub-Variable

- `SINGRA_PREMIUM_REF`
  - Standard ist `master`
  - nützlich für Hotfixes oder einen gezielten Premium-Release-Branch

## Release-Ablauf

1. Core auf den gewünschten Stand bringen.
2. Versionen in `package.json`, `src-tauri/Cargo.toml` und `src-tauri/tauri.conf.json` anheben.
3. Tag im öffentlichen Repository setzen, zum Beispiel `v0.2.0`.
4. GitHub Actions baut die Desktop-Artefakte:
   - Checkout des öffentlichen Repos
   - Checkout des privaten Premium-Repos per `SINGRA_PREMIUM_PAT`
   - Staging des Premium-Source-Codes als Sibling-Repo `../singra-premium`
   - Installation der Core-Dependencies per `npm ci`
   - Tauri-Desktop-Build für Windows, Linux und macOS
   - Signaturen und `latest.json` erzeugen
   - Upload in den GitHub Release

## Warum das mit öffentlichem GitHub-Repo funktioniert

- Die Source-Archive von GitHub enthalten **kein** Premium, weil sie nur aus dem öffentlichen Commit erzeugt werden.
- Die Release-Artefakte werden hingegen im CI gebaut und dürfen den privaten Premium-Checkout verwenden.

## Wichtig für den Updater

- Der konfigurierte Endpoint lautet:
  - `https://github.com/einmalmaik/singravault/releases/latest/download/latest.json`
- Dafür muss der veröffentlichte Release **kein Draft** sein.
- Der Release sollte für diesen Endpoint auch **nicht als GitHub-Prerelease** markiert werden, weil `releases/latest` sonst nicht zuverlässig auf ihn zeigt.
- Wenn die Version noch Beta-Status hat, wird das im Release-Namen und in den Release-Notes gekennzeichnet, nicht über GitHub-Prerelease.

## Sicherheitsgrenze

- Ein öffentlich ausgeliefertes Desktop-Binary kann reverse engineered werden.
- Deshalb dürfen Premium-Funktionen nie nur im Client geschützt sein.
- Echte Premium-Nutzung muss serverseitig geprüft werden.
