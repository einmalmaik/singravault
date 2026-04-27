# Device Key (256-bit)

> Datum: 2026-02-26

## Zusammenfassung

Der Device Key ist ein 256-bit zufälliger Schlüssel, der als zusätzlicher Input in die Key-Ableitung eingespeist wird, nach dem Argon2id-Schritt. Er wird lokal gespeichert: in Tauri über den OS-Keychain-Pfad, im Web/PWA über den Browser Local Secret Store.

Wichtig: Der Browser Local Secret Store ist Defense-in-Depth, aber keine echte OS-Secret-Boundary. Ein kompromittierter Same-Origin-Browser-Kontext kann App-Code und WebCrypto-Operationen missbrauchen. Die stärkere Device-Key-Bindung gilt nur für Desktop-Laufzeiten, in denen der Rust/Tauri-Keychain-Pfad verfügbar ist.

## Architektur

```
OHNE Device Key:   VaultKey = Argon2id(MasterPW, Salt)
MIT Device Key:    VaultKey = HKDF-SHA256(Argon2id(MasterPW, Salt), DeviceKey, "SINGRA_DEVICE_KEY_V1")
```

### Sicherheitsgewinn

| Szenario | Ohne Device Key | Mit Device Key |
|----------|----------------|---------------|
| Server kompromittiert + schwaches PW | Vault knackbar (Brute-Force) | deutlich erschwert; bei Tauri fehlt zusätzlich der OS-Keychain-geschützte Device Key |
| Server kompromittiert + starkes PW | Vault sicher | Vault sicher (doppelt) |
| Gerät gestohlen (ohne PW) | Vault sicher | Vault sicher |
| Gerät gestohlen + PW bekannt | Vault kompromittiert | Vault kompromittiert |

### Vergleich mit 1Password

| Aspekt | Singra Device Key | 1Password Secret Key |
|--------|-------------------|---------------------|
| Stärke | **256-bit** | 128-bit |
| Speicherort | Tauri: OS-Keychain; Web/PWA: Browser Local Secret Store | Keychain/Credential Store |
| Übertragung | QR-Code + Transfer-Geheimnis | QR-Code / Emergency Kit |
| Pflicht | Optional (Migration) | Pflicht |

## Betroffene Dateien

| Datei | Änderung |
|-------|----------|
| `src/services/deviceKeyService.ts` | **NEU** — Kern-Service |
| `src/services/cryptoService.ts` | `deriveKey/deriveRawKey` mit optionalem `deviceKey` |
| `src/contexts/VaultContext.tsx` | Device Key in Setup/Unlock integriert |
| `src/components/settings/DeviceKeySettings.tsx` | **NEU** — Settings UI |

## Funktionen (deviceKeyService.ts)

- `generateDeviceKey()` — Erzeugt 256-bit CSPRNG-Schlüssel
- `storeDeviceKey(userId, key)` — Speichert im gemeinsamen Local Secret Store
- `getDeviceKey(userId)` — Liest aus dem Local Secret Store, migriert alte IndexedDB-Device-Keys wenn möglich
- `hasDeviceKey(userId)` — Prüft ob Device Key existiert
- `deleteDeviceKey(userId)` — Löscht Device Key
- `deriveWithDeviceKey(argon2Output, deviceKey)` — HKDF-Expand Kombination
- `exportDeviceKeyForTransfer(userId, pin)` — Export für QR-Code (PIN-verschlüsselt)
- `importDeviceKeyFromTransfer(userId, data, pin)` — Import von anderem Gerät

## Migration

- Bestehende Nutzer ohne Device Key können weiterhin normal entsperren
- Device Key kann jederzeit in den Einstellungen aktiviert werden
- Bei Aktivierung wird der Vault mit dem kombinierten Key re-verschlüsselt
- Der Device Key wird lokal gespeichert — kein Server-Roundtrip

## Geräteübertragung

1. Nutzer öffnet "Device Key exportieren" auf bestehendem Gerät
2. Wählt ein Transfer-Geheimnis mit mindestens 12 Zeichen
3. Erhält einen versionierten, verschlüsselten Transfer-Code
4. Auf neuem Gerät: "Device Key importieren" → Code + Transfer-Geheimnis eingeben
5. Device Key wird lokal gespeichert, Vault kann entsperrt werden

Transfer-Codes verwenden Version `sv-dk-transfer-v2` mit per-Transfer Salt, Argon2id und AES-GCM. Alte unversionierte PIN-Transfer-Blobs werden nicht mehr importiert, weil sie offline gegen kurze PINs testbar waren.

## Sicherheitshinweise

- **Device Key Verlust**: Wenn der Device Key verloren geht und kein Export existiert, ist der Vault nicht mehr entschlüsselbar. Dies ist by design — es gibt keinen Server-seitigen Recovery-Pfad.
- **Browser-Speicher**: Browser können IndexedDB-Daten löschen (z.B. bei "Browserdaten löschen"). Nutzer sollten einen aktuellen Export ihres Device Keys haben.
- **Web/PWA-Grenze**: Der nicht extrahierbare Browser-Wrapping-Key und IndexedDB schützen gegen einfache lokale Auslese, aber nicht gegen XSS, kompromittierte Extensions oder Same-Origin-JavaScript.
- **Transfer-Grenze**: Während eines expliziten Exports verlässt der Device Key die lokale Laufzeit in verschlüsselter Form. Das Transfer-Geheimnis muss außerhalb des QR-/Transfer-Codes geschützt werden.
