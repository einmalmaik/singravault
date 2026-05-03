# Security Fixes - 2026-03-06

Diese Runde schliesst drei sicherheitsrelevante Luecken aus der laufenden Review.

## 1) CORS Policy gehaertet (Edge Functions)

**Datei:** `supabase/functions/_shared/cors.ts`

**Problem:**
- Preview-Domains wurden pauschal erlaubt (`*.lovable.app`, `*.lovableproject.com`).
- Dadurch konnte jede beliebige Subdomain CORS-freigegeben werden.

**Aenderung:**
- Wildcard-Preview-Allowlist entfernt.
- Neue Opt-in Steuerung eingefuehrt:
  - `ALLOW_PREVIEW_ORIGINS=true`
  - `ALLOWED_PREVIEW_ORIGINS=https://preview-a.example,https://preview-b.example`
- Konfigurationswerte werden strikt validiert (kein `*`, nur gueltige URLs/protokolle).

## 2) Backup-Codes atomar als one-time code verbrauchen

**Datei:** `supabase/functions/auth-session/index.ts`

**Problem:**
- Beim Markieren als benutzt war der Write-Pfad nicht atomar abgesichert.
- Parallel-Requests konnten theoretisch denselben Backup-Code konsumieren.

**Aenderung:**
- Spaltenname korrigiert auf `is_used`.
- Update jetzt atomar mit Guards:
  - `eq('id', validCodeId)`
  - `eq('user_id', user.id)`
  - `eq('is_used', false)`
- Erfolg wird ueber `select(...).maybeSingle()` geprueft.
- Wenn kein Row-Consume erfolgt: `401 Invalid backup code`.

## 3) PQ-Key-Rotation schreibt beide Security-Standard-v1 Key-Spalten

**Migration:** `supabase/migrations/20260306013000_fix_rotate_collection_key_atomic_pq_columns.sql`

**Problem:**
- `rotate_collection_key_atomic(...)` schrieb nur `wrapped_key`.
- Security Standard v1 verlangt konsistente Mirror-Semantik:
  - `wrapped_key = pq_wrapped_key`

**Aenderung:**
- Funktion ersetzt, so dass Inserts immer beide Spalten schreiben.
- Eingabe akzeptiert `pq_wrapped_key` oder Fallback `wrapped_key`.
- Es wird ein gemeinsamer aufgeloester Wert in beide Spalten geschrieben.
- Fehlende Wrapped-Key-Daten fuehren zu einer Exception.

## Verifikation

- Gezielte Security- und Service-Tests in Core/Premium gruen.
- Produktionsbuild in Core/Premium erfolgreich.
- Lint in Core bleibt mit bekannten historischen Repo-Fehlern rot (nicht Teil dieses Fix-Pakets).
