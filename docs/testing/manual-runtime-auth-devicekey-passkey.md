# Manual Runtime Auth, Device Key and Passkey Tests

## Testaccount

Nur lokale/dev/test Umgebungen verwenden. Keine echten Produktions-Credentials.

Env-Beispiel:

```env
VITE_DEV_TEST_ACCOUNT_UI=false
SINGRA_DEV_TEST_ACCOUNT_ENABLED=false
SINGRA_DEV_TEST_EMAIL=
SINGRA_DEV_TEST_PASSWORD=
SINGRA_DEV_TEST_MASTER_PASSWORD=
SINGRA_DEV_TEST_CREATE_USER=false
SINGRA_DEV_TEST_AUTO_CONFIRM=false
SUPABASE_SERVICE_ROLE_KEY=
```

Passwörter und Service-Role-Key dürfen nie in `VITE_*` stehen. `SINGRA_DEV_TEST_ACCOUNT_ENABLED=true` darf nur lokal in `.env.local` gesetzt sein; Production-Builds brechen damit ab.

## Browser

1. `npm run dev` starten.
2. Frisches Browserprofil oder Incognito öffnen.
3. Neu anmelden und `/vault` öffnen.
4. Ohne Device Key muss `master_only` mit Master-Passwort entsperren.
5. `/vault/settings` öffnen; Konsole muss frei von Provider-/Hook-/`Invalid hook call`-Fehlern sein.

## Device Key

1. Vault entsperren.
2. `/vault/settings` -> Sicherheit -> Device Key aktivieren.
3. Master-Passwort eingeben und Warnung bestätigen.
4. Transfer Secret anzeigen, manuell kopieren und optional als Datei herunterladen.
5. Device-Key-Export erzeugen und als `.singra-device-key` herunterladen.
6. In frischem Browserprofil anmelden. Account-Login darf funktionieren.
7. Vault-Unlock ohne Import muss mit Device-Key-fehlt-Fehler blockieren.
8. Exportdatei importieren, Transfer Secret eingeben, erneut entsperren.
9. Falsches Transfer Secret und malformed Datei testen: Import muss fehlschlagen und darf vorhandene Keys nicht überschreiben.

## PWA

1. Lokale App als PWA installieren, soweit Browser dies erlaubt.
2. Mit Account anmelden, der im Browser Device Key required aktiviert hat.
3. Account-Login darf funktionieren.
4. Vault-Unlock muss ohne importierten Device Key blockieren.
5. Device-Key-Import per Datei/Text wiederholen.

## Tauri

1. `npm run tauri:dev` starten.
2. Anmelden und Vault entsperren.
3. Device Key aktivieren. Falls OS-Keychain nicht verfügbar ist, muss die UI klar blockieren.
4. Exportdatei und Transfer Secret erzeugen.
5. Lokalen Keychain-Eintrag in einer separaten Testumgebung entfernen oder neuen OS-Testuser nutzen.
6. Import mit richtigem/falschem Secret prüfen.

## Passkey/WebAuthn

1. In `/vault/settings` Passkey hinzufügen.
2. Plattform ohne WebAuthn muss eine klare Unsupported-Meldung zeigen.
3. Benutzerabbruch darf keinen Success-State erzeugen.
4. Duplicate Credential muss fehlschlagen und vorhandene Credentials behalten.
5. Nach Logout, Refresh und Vault-Lock mit Passkey entsperren.
6. Wenn PRF nicht verfügbar ist, darf die UI keine Vault-Unlock-Fähigkeit behaupten.

## Vault Lock/Unlock und 2FA

1. Account ohne 2FA: Vault-Unlock darf keine 2FA verlangen.
2. Account mit Account-2FA, aber VaultFA aus: Login-2FA bleibt Account-Flow; Vault-Unlock verlangt keine 2FA.
3. VaultFA an: Vault-Unlock verlangt 2FA und bleibt bei Abbruch locked.
4. Device-Key-required ohne Device Key: Fehlermeldung muss Device Key nennen, nicht 2FA.
5. Lock -> Unlock ohne erneuten Account-Login muss funktionieren.

## Konsole

Harmlose Dev-Warnungen:

- React Router future flags.
- Vite HMR Meldungen.

Blocker:

- `must be used within a ...Provider`
- `Invalid hook call`
- Device-Key-required Unlock gelingt ohne lokalen Device Key
- 2FA wird bei eindeutig deaktivierter VaultFA verlangt
- Secrets in Logs, Toasts, URLs oder Console
