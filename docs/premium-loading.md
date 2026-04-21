# Optional Premium Loading

Der öffentliche Core muss ohne das private Paket `@singra/premium` installierbar, testbar und buildbar bleiben.

## Auflösungsreihenfolge

`@singra/premium` wird in dieser Reihenfolge aufgelöst:

1. In der lokalen Entwicklung auf das Sibling-Repo `../singra-premium`, falls vorhanden
2. sonst auf ein installiertes Paket in `node_modules/@singra/premium`
3. sonst auf den lokalen Stub unter `src/extensions/premiumStub.ts`

## Wichtige Schalter

- `SINGRA_DISABLE_PREMIUM=true`
  - erzwingt den Stub
- `SINGRA_PREMIUM_SOURCE=true`
  - erzwingt in passenden Szenarien die Verwendung des Sibling-Source-Repos
- `INSTALL_SINGRA_PREMIUM=true`
  - injiziert das private Paket im Build- oder CI-Kontext

## Lokale Workflows

### Core-only

```bash
npm install
npm run dev:core-only
npm run build:core-only
npm run tauri:dev:core-only
npm run tauri:build:core-only
```

### Premium lokal

Voraussetzung:

- `../singra-premium` existiert oder
- `@singra/premium` ist installiert

Dann reichen die normalen Skripte:

```bash
npm install
npm run dev
npm run build
npm run tauri:dev
npm run tauri:build
```

## CI und Release-Builds

Für CI, Vercel und Desktop-Releases gibt es die generische Install-Logik:

- [`scripts/install-with-optional-premium.mjs`](../scripts/install-with-optional-premium.mjs)

Sie:

- injiziert das private Paket nur dann, wenn `INSTALL_SINGRA_PREMIUM=true` gesetzt ist
- verwendet `GITHUB_PAT` für den Zugriff auf `einmalmaik/singra-premium`
- löscht das Lockfile im temporären Build-Workspace, damit die Auflösung konsistent neu erfolgt
- führt anschließend `npm install` aus

## Vercel

Wenn Vercel weiterhin dieselbe Logik nutzen soll, kann der bestehende Einstieg bestehen bleiben:

- [`scripts/vercel-install.mjs`](../scripts/vercel-install.mjs)

Dieser delegiert intern an die generische Install-Logik.
