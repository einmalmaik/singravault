# Device Key (256 Bit)

> Stand: 2026-04-28

## Kurzfassung

Der Device Key ist ein lokal gespeicherter 32-Byte-Zufallsschlüssel. Er wird nicht aus E-Mail, User-ID oder Master-Passwort abgeleitet und wird nicht auf den Server geschrieben. Wenn Device-Key-Schutz aktiv ist, fließt er nach Argon2id per HKDF-SHA-256 in die Vault-Key-Ableitung ein:

```text
Master-Passwort + Salt -> Argon2id -> raw KDF output
raw KDF output + Device Key -> HKDF-SHA-256("SINGRA_DEVICE_KEY_V1") -> finaler KDF output
finaler KDF output -> UserKey-Wrapper oder Legacy-Vault-Key
```

Bei aktuellen Vaults mit `encrypted_user_key` werden Vault-Einträge nicht direkt mit dem KDF-Output verschlüsselt. Der Device Key schützt dort den Wrapper des zufälligen UserKey. Ohne Master-Passwort und Device Key kann der UserKey nicht entpackt werden. Legacy-Vaults ohne UserKey werden beim Aktivieren vollständig auf den Device-Key-geschützten Key umverschlüsselt.

## Sicherheitswirkung

Der Device Key schützt gegen reine Serverkompromittierung, wenn der Angreifer nur Datenbank/API/Edge-Daten sieht. Er hilft nicht gegen kompromittierte Geräte, Malware, XSS, bösartige Browser-Erweiterungen oder eine kompromittierte Laufzeit nach dem Unlock.

Desktop/Tauri und Web/PWA sind nicht gleich stark:

- Tauri/Desktop speichert `device-key:<user-uuid>` über Rust `keyring` im OS-Secret-Store. Die Tauri-Commands sind auf `device-key:<uuid>` und `vault-integrity:<uuid>` begrenzt.
- Web/PWA speichert über IndexedDB plus nicht-extrahierbaren WebCrypto-Wrapping-Key. Das ist Defense-in-Depth gegen einfache lokale Auslese, aber keine OS-Keychain-Grenze. Same-Origin-JavaScript, XSS, Extensions oder lokale Malware können die App-Laufzeit missbrauchen.

## Erzeugung und Speicherung

- Erzeugung: `generateDeviceKey()` nutzt `crypto.getRandomValues(new Uint8Array(32))`.
- Validierung: gespeicherte, importierte und abgeleitete Device-Key-Werte müssen exakt 32 Byte lang sein.
- Speicherung: `storeDeviceKey(userId, key)` schreibt in `src/platform/localSecretStore.ts`.
- Löschen: Reset/Recovery löscht Device Key, Offline-Daten und Integrity-Baseline lokal.
- Memory-Cleanup: temporäre Byte-Arrays werden best-effort mit `fill(0)` überschrieben. JavaScript garantiert keine vollständige Speicherbereinigung.

## Unlock und Verlust

Ein Device-Key-geschützter Vault lässt sich ohne den korrekten Device Key nicht entschlüsseln. Wenn der lokale Device Key verloren geht und kein Export/Transfer existiert, gibt es keinen serverseitigen Recovery-Pfad für die verschlüsselten Daten.

Wichtig: Es gibt aktuell kein serverseitiges `device_key_required`-Flag. Auf einem neuen Gerät ohne lokalen Key kann der Client deshalb nicht immer zwischen "falsches Master-Passwort" und "Device Key fehlt" unterscheiden. Kryptografisch bleibt der Unlock blockiert, die UX kann aber generisch wirken.

## Import und Transfer

Import existiert, weil der Device Key den Zugriff bewusst an ein Gerät bindet. Ein neues Gerät oder zweiter Desktop braucht den gleichen lokalen Faktor. Dieser Faktor darf nicht serverseitig im Klartext liegen, deshalb gibt es einen expliziten, nutzergestarteten Transfer.

Transferformat:

- Prefix: `sv-dk-transfer-v2:`
- Envelope: JSON, base64-codiert
- KDF: Argon2id, exakt `memory=65536`, `iterations=3`, `parallelism=1`, `hashLength=32`
- Encryption: AES-256-GCM mit zufälligem 16-Byte-Salt und 12-Byte-IV
- Transfer Secret: mindestens 20 Zeichen; die UI bietet ein zufälliges Secret an

Import-Regeln:

- falsches Transfer Secret überschreibt nichts,
- malformed Envelope überschreibt nichts,
- Device Keys mit falscher Länge werden abgelehnt,
- KDF-Downgrades und extreme KDF-Parameter werden abgelehnt,
- ein vorhandener lokaler Device Key wird nicht still überschrieben.

Risiken bleiben: Ein abgefangener Transfer-Code kann offline gegen das Transfer Secret geprüft werden. Deshalb muss das Transfer Secret zufällig und getrennt vom QR-/Export-Code übertragen werden. QR-Screenshots, Clipboard-History und Chat-Uploads sind unsichere Transportwege.

## Erlaubte Claims

- "Zusätzlicher lokaler 256-Bit-Faktor."
- "Schützt gegen reine Serverkompromittierung, wenn der Device-Key-Schutz aktiv ist."
- "Desktop/Tauri kann OS-Keychain-gestützten Schutz bieten."
- "Web/PWA ist Defense-in-Depth, aber keine OS-Keychain-Grenze."

## Nicht erlaubte Claims

- "Schützt gegen XSS."
- "Schützt gegen Malware oder bösartige Browser-Erweiterungen."
- "Browser-Speicher ist gleich stark wie OS-Keychain."
- "Verlust ist serverseitig wiederherstellbar."
