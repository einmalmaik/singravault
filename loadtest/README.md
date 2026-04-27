# k6 Load Testing

Dieses Verzeichnis enthaelt reproduzierbare Lasttest-Skripte fuer die wichtigsten Backend-Pfade:

- `scenarios/login.js`: deaktiviert, bis ein OPAQUE-faehiger k6-Login-Harness existiert. Direkter Supabase-Passwortgrant ist blockiert.
- `scenarios/vault-read.js`: Default Vault + Kategorien + Vault-Items lesen.
- `scenarios/vault-mutate.js`: Vault-Item Upsert/Delete (Schreiblast).
- `scenarios/offline-sync-replay.js`: Batch-Upserts als Offline-Sync-Replay + Refresh.

## Voraussetzungen

1. `k6` lokal installiert.
2. Testumgebung (nicht Produktion) mit dedizierten Test-Usern.
3. Umgebungsvariablen gesetzt.

## Pflicht-Umgebungsvariablen

Fuer alle Szenarien:

- `SUPABASE_URL`: z. B. `https://<project>.supabase.co`
- `SUPABASE_ANON_KEY` (oder `VITE_SUPABASE_PUBLISHABLE_KEY`)

Fuer automatische Test-User-Erstellung und Token-Generierung:

- `SUPABASE_SERVICE_ROLE_KEY`

Fuer Token-basierte Szenarien (`vault-read`, `vault-mutate`, `offline-sync-replay`):

- `K6_TOKENS`: kommaseparierte oder zeilengetrennte Bearer-Token
- alternativ `K6_TOKENS_FILE`: Datei mit einem Token pro Zeile

Fuer ein kuenftiges OPAQUE-Login-Szenario:

- `K6_LOGIN_USERS`: derzeit nicht produktiv nutzbar, weil direkte Passwortgrants absichtlich deaktiviert sind.
- Ein OPAQUE-Login-Lasttest muss OPAQUE-Protokollnachrichten erzeugen und darf kein App-Passwort an Supabase Auth senden.

## Optionale Umgebungsvariablen

- `K6_PROFILE`: `smoke`, `default`, `10k`
- `K6_CUSTOM_STAGES`: JSON-Array ueberschreibt alle Profile
- `K6_KEEP_BODIES`: `true|false` (Default `true`, notwendig fuer token/user/vault parsing)
- `K6_SLEEP_SECONDS`: Denkzeit zwischen Iterationen
- `K6_HTTP_P95_THRESHOLD`: z. B. `p(95)<1000`
- `K6_HTTP_FAILED_THRESHOLD`: z. B. `rate<0.02`
- `K6_ITEMS_LIMIT`: Limit fuer Item-Leseaufrufe (Default `200`)
- `K6_MUTATE_CLEANUP`: `true|false` (Default `true`)
- `K6_SYNC_BATCH_SIZE`: Batch-Groesse im Offline-Replay (Default `5`)
- `K6_SYNC_CLEANUP`: `true|false` (Default `true`)
- `K6_BIN`: optionaler Pfad zur `k6` Binary (wenn `k6` nicht im PATH ist)
- `TOKEN_GEN_BATCH_SIZE`: Parallelitaet bei Token-Generierung (Default `20`)
- `TOKEN_GEN_MAX_RETRIES`: Retries bei Auth-Rate-Limit (Default `5`)
- `TOKEN_GEN_RETRY_BASE_MS`: Basis-Backoff in ms (Default `300`)

## NPM-Kommandos

- `npm run loadtest:seed-users`
- `npm run loadtest:gen-tokens`
- `npm run loadtest:prepare`
- `npm run loadtest:smoke`
- `npm run loadtest:login`
- `npm run loadtest:vault-read`
- `npm run loadtest:10k`
- `npm run loadtest:vault-mutate`
- `npm run loadtest:offline-sync`

## Auto-Setup (empfohlen)

```powershell
$env:SUPABASE_URL="https://your-project.supabase.co"
$env:SUPABASE_ANON_KEY="your-anon-key"
$env:SUPABASE_SERVICE_ROLE_KEY="your-service-role-key"
$env:TEST_USERS_COUNT="50"
npm run loadtest:prepare
```

Wenn bei Token-Generierung Rate-Limits auftreten:

```powershell
$env:TOKEN_GEN_BATCH_SIZE="5"
$env:TOKEN_GEN_MAX_RETRIES="8"
$env:TOKEN_GEN_RETRY_BASE_MS="500"
npm run loadtest:gen-tokens
```

Danach liegen:

- Userliste in `loadtest/users.txt`
- Tokenliste in `loadtest/tokens.txt`

Du kannst dann direkt starten:

```powershell
$env:K6_TOKENS_FILE="loadtest/tokens.txt"
npm run loadtest:smoke
```

## Beispiel (PowerShell)

```powershell
$env:SUPABASE_URL="https://your-project.supabase.co"
$env:SUPABASE_ANON_KEY="your-anon-key"
$env:K6_TOKENS_FILE="loadtest/tokens.txt"
npm run loadtest:vault-read
```

## Hinweise

- Schreibszenarien veraendern Daten. Standardmaessig wird aufgeraeumt (`delete`), aber die Last auf DB bleibt bestehen.
- Fuer 10k gleichzeitig solltest du ein Token-Pool mit vielen Test-Usern nutzen, damit RLS-/Hot-Row-Effekte realistischer sind.
- Login-Lasttests koennen Auth-Rate-Limits triggern. Dafuer dedizierte Testkonten verwenden.
