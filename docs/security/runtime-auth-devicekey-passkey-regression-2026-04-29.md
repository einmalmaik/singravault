# Runtime Auth/Device-Key/Passkey Regression - 2026-04-29

Arbeitsstand: Branch `feat/device-passkey-fixes`, Basis `v0.4.3` / `origin/main`.

| ID | Bereich | Plattform | Schritte | Erwartet | Ist | Status |
|---|---|---|---|---|---|---|
| DK-01 | Device Key | Web lokal | Neuer Account, Master-Passwort setzen, Vault ohne Device Key entsperren | Unlock funktioniert mit `master_only` | Codepfad erlaubt Unlock ohne Device Key | verifiziert per Code/Test |
| DK-02 | Device Key | Web lokal | Device Key aktivieren | Secret Store und Crypto-Rewrap müssen vor Server-State erfolgreich sein | Rewrap vorhanden; Backup wurde aber schon vor Export als bestätigt markiert | behoben |
| DK-03 | Device Key | Web lokal | Transfer Secret generieren | Secret sichtbar/kopierbar/downloadbar | Secret war nur Passwortfeld, generiertes Secret nicht praktisch exportierbar | behoben |
| DK-04 | Device Key | Web lokal | Device-Key-Export erzeugen | `.singra-device-key`-Datei oder Text nutzbar | Nur Textblock, kein Dateiexport | behoben |
| DK-05 | Device Key | Web lokal/frischer Kontext | Falsches Secret importieren | Import schlägt fehl und überschreibt nichts | Service-Test deckt Nicht-Überschreiben ab | verifiziert per Test |
| DK-06 | Device Key | Web lokal/frischer Kontext | Malformed Import | Import schlägt fehl und überschreibt nichts | Web war robust; Native-Fehler konnten zur UI durchwerfen | behoben |
| DK-07 | Device Key | Tauri lokal | Device Key aktivieren/exportieren/importieren | OS-Keychain-Pfad muss funktionieren oder klar blockieren | Native Pfad vorhanden; manuelle Tauri-Prüfung steht noch aus | offen: manuell |
| DK-08 | Enforcement | Web/Tauri/PWA | Account-Login auf neuem Gerät, Vault-Unlock ohne Device Key | Login erlaubt, Vault-Unlock blockiert mit Device-Key-Fehler | `getRequiredDeviceKey` blockiert ohne Key; kein Master-only-Fallback gefunden | verifiziert per Code/Testbestand |
| PK-01 | Passkey | Web lokal | Passkey hinzufügen | Unsupported/Cancel/Duplicate sauber melden | Fehler wurden teils roh durchgereicht | teilweise gehärtet |
| PK-02 | Passkey | Web lokal | Passkey Login mit PRF | Nur 32-Byte PRF/Vault-Key-Material akzeptieren | Längenvalidierung war nicht strikt an allen Grenzen | behoben |
| PK-03 | Passkey | Tauri/PWA | Passkey hinzufügen/Login | RP-ID/Origin muss zur Oberfläche passen | Server unterscheidet Origin/RP; manuelle Plattformprüfung steht aus | offen: manuell |
| AUTH-01 | Auth-State | Web lokal | Login, Refresh, `/vault/settings` direkt öffnen | Nicht gleichzeitig eingeloggt/ausgeloggt | Auth/Vault sind getrennt; keine zentrale Runtime-State-API vorhanden | teilweise offen |
| AUTH-02 | Dev/Test | Web/Tauri | Production-Build mit `VITE_E2E_TEST_MODE=true` | Build muss hart fehlschlagen | Guardrail fehlte | behoben |
| 2FA-01 | Vault Unlock | Web lokal | Account ohne VaultFA, Edge Function transient fehlerhaft | Kein falsches Vault-2FA, wenn DB eindeutig disabled sagt | Client fiel fail-closed auf Vault-2FA | behoben |
| 2FA-02 | Vault Unlock | Web lokal | Device-Key-required ohne lokalen Key | Device-Key-Fehler, kein 2FA-Fehler | Device-Key-Check läuft vor 2FA-Key-Release | verifiziert per Code |
| LOCK-01 | Vault Lock | Web lokal | Unlock, Lock, erneuter Unlock | Account-Session bleibt, Vault-Key-State wird gelöscht | bestehender Code trennt `lock()`/`signOut()` | verifiziert per Code, manuell offen |

## Reproduktionsnotizen

- Device-Key-Backup-Bestätigung war fachlich falsch: `device_key_backup_acknowledged_at` wurde schon beim Aktivieren gesetzt, bevor der Nutzer einen Export erzeugt hatte.
- Der zufällig generierte Transfer Secret war nicht zuverlässig sichtbar, kopierbar oder als Datei sicherbar.
- Native Device-Key-Import konnte malformed/native Fehler als Promise-Rejection in die UI tragen. Import wird jetzt als `false` normalisiert, ohne vorhandene Keys zu überschreiben.
- Vault-2FA-Erkennung war zu grob: ein transienter `auth-2fa`-Fehler führte bei `vault_unlock` sofort zu `required=true`, obwohl ein direkter `user_2fa`-Read eindeutig `vault_2fa_enabled=false` liefern kann.
- Passkey PRF/Vault-Key-Material wird jetzt an den kryptografischen Grenzen auf exakt 32 Byte geprüft.

## Noch manuell zu prüfen

- Tauri Device-Key-Aktivierung und OS-Keychain-Verfügbarkeit.
- `/vault/settings` im Browser und Tauri öffnen und Konsole auf doppelte Context-/Hook-Pfade prüfen.
- PWA/mobile WebAuthn RP-ID/Origin-Verhalten.
- Echte WebAuthn-Flows: Benutzerabbruch, Duplicate Credential, abgelaufene Challenge.
