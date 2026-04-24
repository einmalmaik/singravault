# Security Fixes — 2026-02-26

Basierend auf dem Audit `docs/security-audit-2026-02-26.md` wurden folgende 3 kritische Punkte behoben.

> Historischer Fix-Stand. App-Passwort-Login läuft seit dem OPAQUE-Cutover vom 2026-04-24 nicht mehr über `auth-session` oder serverseitige Argon2id-Passworthashes.

---

## Fix 1: `backup_codes.used` → `is_used` (auth-session)

**Datei:** `supabase/functions/auth-session/index.ts`

Die Edge Function nutzte die nicht existierende Spalte `used` statt `is_used` beim Filtern ungenutzter Backup-Codes. Das führte dazu, dass 2FA-Backup-Code-Logins komplett fehlschlugen.

**Änderung:** `.eq('used', false)` → `.eq('is_used', false)`

---

## Fix 2: TOTP Secret über RPC statt Plaintext-Spalte (auth-session)

**Datei:** `supabase/functions/auth-session/index.ts`

Die Edge Function las `totp_secret` (Plaintext-Spalte) direkt aus der `user_2fa`-Tabelle. Korrekt ist die Nutzung des `get_user_2fa_secret` RPC, der die verschlüsselte Spalte `totp_secret_enc` entschlüsselt und den Plaintext-Fallback migriert.

**Änderung:**
- SELECT entfernt `totp_secret` aus der Query (nur noch `is_enabled`)
- TOTP-Verifikation nutzt jetzt `supabaseAdmin.rpc('get_user_2fa_secret', { p_user_id, p_require_enabled: true })`

---

## Fix 3: Argon2id Parameter-Härtung (auth-register, auth-reset-password)

**Dateien:**
- `supabase/functions/auth-register/index.ts`
- `supabase/functions/auth-reset-password/index.ts`

Die serverseitigen Argon2id-Parameter waren deutlich schwächer als die clientseitigen (19 MiB / 2 Iterationen vs. 128 MiB / 3 Iterationen).

**Änderung:**
- `memorySize`: 19456 → 65536 (64 MiB)
- `iterations`: 2 → 3

**Hinweis:** 128 MiB wäre ideal, aber Edge Functions haben begrenzte Speicherressourcen. 64 MiB ist ein guter Kompromiss.

---

## Verifikation

- Backup-Code-Login sollte jetzt funktionieren
- TOTP-Login nutzt den verschlüsselten Pfad
- Neue Registrierungen und Passwort-Resets verwenden stärkere KDF-Parameter
