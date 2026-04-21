# Singra Vault

> **Beta-Status:** `0.2.1 Beta`
>
> Web, PWA und Desktop werden aktiv weiterentwickelt. Die Desktop-App ist funktionsfähig, aber noch nicht als final stabil freigegeben.

**Live-Instanz:** [singravault.mauntingstudios.de](https://singravault.mauntingstudios.de)

## Überblick

Singra Vault ist ein Zero-Knowledge Passwort-Manager mit Fokus auf Datenschutz, lokaler Verschlüsselung und klarer Trennung zwischen öffentlichem Core und privatem Premium-Bereich.

Dieses Repository enthält den **öffentlichen Core**:

- Web-App
- PWA
- Tauri-Desktop-Basis
- Self-Hosting-fähige Kernfunktionen

Nicht in diesem Repository enthalten:

- Abonnement-Logik
- Billing- und Support-Oberflächen
- Admin-Bereich
- private Premium- und Family-Funktionen

Diese Teile bleiben im privaten Paket `@singra/premium`.

## Sicherheitsmodell

Singra Vault verfolgt einen **Zero-Knowledge** Ansatz:

- Verschlüsselung und Entschlüsselung passieren clientseitig
- das Master-Passwort verlässt das Gerät nicht im Klartext
- sensible Schlüsselableitung erfolgt lokal
- serverseitige Dienste dürfen keinen Zugriff auf entschlüsselte Tresor-Inhalte haben

Technische Eckpunkte:

- **Verschlüsselung:** AES-GCM
- **KDF:** Argon2id
- **Passkeys / WebAuthn:** plattformabhängig pro Origin bzw. RP-ID
- **Desktop-Session:** Refresh-Token im OS-Keychain, Access-Token nur im Speicher

## Core vs. Premium

### Core

Der öffentliche Core ist für Self-Hosting gedacht und umfasst die grundlegenden Passwortmanager-Funktionen:

- Tresor
- Passwortgenerator
- sichere Notizen
- lokale Verschlüsselung
- Passkey-/Entsperrpfade
- PWA- und Desktop-Basis

### Premium

Premium wird **nicht** in dieses Repository eingecheckt.

- In lokaler Entwicklung wird Premium nur geladen, wenn das private Sibling-Repo vorhanden ist.
- In Deployments und Release-Builds wird Premium nur über private Build-Zugriffe injiziert.
- Fehlt das Paket, läuft der Core sauber mit einem Stub weiter.

Details: [`docs/premium-loading.md`](docs/premium-loading.md)

## Voraussetzungen

- Node.js `>= 20.19.0`
- npm
- ein Supabase-Projekt für Self-Hosting
- für Desktop-Builds zusätzlich die üblichen Tauri-Systemvoraussetzungen

## Umgebungsvariablen

Beispiel: [`env.example`](env.example)

Mindestens erforderlich:

- `VITE_SUPABASE_PROJECT_ID`
- `VITE_SUPABASE_PUBLISHABLE_KEY`
- `VITE_SUPABASE_URL`
- `VITE_SITE_URL`

## Lokale Entwicklung

### Schnellstart für Self-Hosting

```bash
git clone https://github.com/einmalmaik/singravault.git
cd singravault
cp env.example .env
npm install
```

Danach die Werte in `.env` für das eigene Supabase-Projekt eintragen.

### Web / PWA

```bash
npm run dev
```

Danach läuft die App unter `http://localhost:8080`.

### Core-only, auch wenn lokal ein Premium-Repo existiert

```bash
npm install
npm run dev:core-only
```

### Desktop lokal starten

Wenn **kein** Premium-Repo installiert oder daneben vorhanden ist:

```bash
npm install
npm run tauri:dev
```

Wenn lokal zwar Premium vorhanden ist, du aber bewusst nur den öffentlichen Core testen willst:

```bash
npm install
npm run tauri:dev:core-only
```

## Builds

### Web-Build

```bash
npm run build
```

### Core-only Desktop-Build

```bash
npm run tauri:build:core-only
```

## Release-Modell

Das öffentliche Repository bleibt **Core-only**.

Desktop-Releases dürfen trotzdem mit Premium gebaut werden, solange:

- das private Premium-Paket nur im CI injiziert wird
- der Premium-Source-Code nie ins öffentliche Repo gelangt
- Premium-Funktionen serverseitig abgesichert bleiben

Details: [`docs/desktop-release-process.md`](docs/desktop-release-process.md)

## GitHub Actions

Es gibt zwei Workflows:

- `ci.yml`
  - typprüft und baut den öffentlichen Core
- `release-desktop.yml`
  - baut signierte Tauri-Desktop-Artefakte aus einem öffentlichen Tag
  - injiziert Premium nur während des CI-Builds
  - injiziert für offizielle Desktop-Releases zusätzlich die gehostete Singra-Supabase-Konfiguration
  - lädt die Release-Artefakte und `latest.json` für den Updater hoch

### Offizielle Desktop-Releases

Die veröffentlichten Desktop-Installer dürfen direkt mit der gehosteten Singra-Instanz funktionieren, ohne dass Self-Hoster-Werte in den öffentlichen Source-Code gelangen.

Dafür liest `release-desktop.yml` diese Repository-Variablen nur im GitHub-Action-Build:

- `OFFICIAL_VITE_SUPABASE_PROJECT_ID`
- `OFFICIAL_VITE_SUPABASE_PUBLISHABLE_KEY`
- `OFFICIAL_VITE_SUPABASE_URL`
- `OFFICIAL_VITE_SITE_URL`

Fehlt eine dieser Variablen, schlägt der Release-Build bewusst fehl, statt einen unkonfigurierten Installer zu veröffentlichen.

## Updater

Die Desktop-App nutzt Tauri Updater mit signierten Release-Artefakten.

Wichtig:

- `latest.json` muss in einem veröffentlichten GitHub Release liegen
- der private Signierschlüssel darf niemals ins Repository
- `.env` reicht für den Build des Updaters nicht, die Signaturdaten müssen als echte Umgebungsvariablen oder GitHub-Secrets gesetzt werden

Für private Premium-Builds in GitHub Actions wird zusätzlich ein Repository-Secret `SINGRA_PREMIUM_PAT` benötigt, das Lesezugriff auf `einmalmaik/singra-premium` hat.

## Lizenz

Dieses Projekt ist unter der **Business Source License 1.1 (BUSL-1.1)** lizenziert.

- Quellcode öffentlich einsehbar: ja
- Self-Hosting für private Nutzung: ja
- kommerzielles Hosting / Weiterverkauf: nur mit Genehmigung

Siehe [`LICENSE`](LICENSE).
