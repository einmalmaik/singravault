# Device Key (256-bit)

> Datum: 2026-02-26

## Zusammenfassung

Der Device Key ist ein 256-bit zufälliger Schlüssel, der auf dem Gerät des Nutzers in IndexedDB gespeichert wird und **nie** an den Server gesendet wird. Er wird als zusätzlicher Input in die Key-Ableitung eingespeist, NACH dem Argon2id-Schritt.

## Architektur

```
OHNE Device Key:   VaultKey = Argon2id(MasterPW, Salt)
MIT Device Key:    VaultKey = HKDF-SHA256(Argon2id(MasterPW, Salt), DeviceKey, "SINGRA_DEVICE_KEY_V1")
```

### Sicherheitsgewinn

| Szenario | Ohne Device Key | Mit Device Key |
|----------|----------------|---------------|
| Server kompromittiert + schwaches PW | Vault knackbar (Brute-Force) | Vault sicher (Device Key fehlt) |
| Server kompromittiert + starkes PW | Vault sicher | Vault sicher (doppelt) |
| Gerät gestohlen (ohne PW) | Vault sicher | Vault sicher |
| Gerät gestohlen + PW bekannt | Vault kompromittiert | Vault kompromittiert |

### Vergleich mit 1Password

| Aspekt | Singra Device Key | 1Password Secret Key |
|--------|-------------------|---------------------|
| Stärke | **256-bit** | 128-bit |
| Speicherort | IndexedDB (verschlüsselt) | Keychain/Credential Store |
| Übertragung | QR-Code + PIN-Verschlüsselung | QR-Code / Emergency Kit |
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
- `storeDeviceKey(userId, key)` — Speichert verschlüsselt in IndexedDB
- `getDeviceKey(userId)` — Liest aus IndexedDB
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
2. Wählt einen Transfer-PIN (min. 4 Zeichen)
3. Erhält einen verschlüsselten Code (Base64)
4. Auf neuem Gerät: "Device Key importieren" → Code + PIN eingeben
5. Device Key wird lokal gespeichert, Vault kann entsperrt werden

## Sicherheitshinweise

- **Device Key Verlust**: Wenn der Device Key verloren geht und kein Export existiert, ist der Vault nicht mehr entschlüsselbar. Dies ist by design — es gibt keinen Server-seitigen Recovery-Pfad.
- **IndexedDB**: Browser können IndexedDB-Daten löschen (z.B. bei "Browserdaten löschen"). Nutzer sollten immer einen Export ihres Device Keys haben.
- **Wrapping**: Der Device Key wird in IndexedDB mit einem aus der userId abgeleiteten Schlüssel verschlüsselt. Dies ist Defense-in-Depth, nicht der primäre Schutzmechanismus.
