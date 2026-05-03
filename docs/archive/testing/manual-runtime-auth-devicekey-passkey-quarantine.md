# Manual Runtime Tests: Auth, Device Key, Passkey, Quarantine

## Dev-Testaccount Setup

Lege echte Werte nur in `.env.local` ab:

```bash
SINGRA_DEV_TEST_ACCOUNT_ENABLED=true
SINGRA_DEV_TEST_EMAIL=dev-test@example.local
SINGRA_DEV_TEST_PASSWORD=
SINGRA_DEV_TEST_MASTER_PASSWORD=
SINGRA_DEV_TEST_CREATE_USER=true
SINGRA_DEV_TEST_AUTO_CONFIRM=true
SINGRA_DEV_TEST_RESET_VAULT=false
SUPABASE_SERVICE_ROLE_KEY=
```

`npm run dev` und `npm run tauri:dev` führen `scripts/dev/ensure-dev-test-account.mjs` aus. Fehlen Werte, ist das Script ein No-op. Der Account wird nicht automatisch eingeloggt.

## Web / PWA / Tauri

1. `npm run dev` starten.
2. Frisches Browserprofil oder Inkognito öffnen.
3. Erwartung: ohne Login ist kein User aktiv.
4. Mit echtem Account oder Dev-Testaccount regulär anmelden.
5. `/settings` öffnen: Account Settings müssen ohne Vault-Unlock erreichbar sein.
6. `/vault` öffnen: Vault muss locked bleiben, bis Master/Device-Key/Passkey-Unlock erfolgreich ist.
7. Logout ausführen und refreshen: Account-, Vault-, Device-Key-, 2FA- und Quarantäne-Runtime-State müssen leer sein.
8. `npm run tauri:dev` starten und dieselben Schritte durchführen.

## Device Key

1. Vault unlocken.
2. Device Key aktivieren.
3. Export als `.singra-device-key` durchführen; Secret separat notieren.
4. In frischem Browser/PWA/Tauri anmelden.
5. Erwartung: Account Login erlaubt, Vault Unlock ohne Import blockiert mit Device-Key-Missing.
6. Import mit falschem Secret: darf nichts überschreiben.
7. Import mit richtigem Secret: Unlock möglich.

## Passkey/WebAuthn

1. Plattform-Support prüfen.
2. Passkey hinzufügen.
3. Duplicate Credential testen: klarer Fehler.
4. Challenge abbrechen: kein halb eingeloggter Zustand.
5. Logout/Login/Refresh wiederholen.
6. Tauri/Web Origin/RP-ID beachten: Passkeys sind origin-/RP-ID-gebunden.

## Quarantäne / Integrität

1. Single-Item-Fixture mit geändertem Ciphertext laden.
2. Erwartung: nur dieses Item quarantined; es wird nicht entschlüsselt, andere Items bleiben nutzbar.
3. Missing/unknown Item Fixture testen: Item-Quarantäne.
4. Kategorie-Fixture mit geändertem Namen/Icon/Color testen.
5. Erwartung: Vault blockiert mit `category_structure_mismatch`.
6. Malformed Baseline testen.
7. Erwartung: Vault blockiert mit `baseline_unreadable` oder `snapshot_malformed`.

## Erwartete Konsolenmeldungen

- Keine `must be used within a ...Provider`.
- Kein `Invalid hook call`.
- Keine doppelte Core-Modulidentität über `/@fs/` und `/src/`.
- Device-Key-Missing, Quarantäne und 2FA müssen unterschiedliche Fehlertexte haben.

## Echte Blocker

- Web und Tauri treffen bei gleichem Snapshot unterschiedliche Integrity-Entscheidungen.
- `?tauriDevAuth=1` oder localStorage erzeugt Account-Session.
- Production-Build akzeptiert aktivierten Dev-Testaccount.
- Device-Key-required kann mit Master-Passwort allein unlocken.
