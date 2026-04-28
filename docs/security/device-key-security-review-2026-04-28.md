# Device-Key-Sicherheitsreview

> Datum: 2026-04-28  
> Branch: `feat/zero-knowledge.hardering`

## Ist-Architektur

Der Device Key ist ein 32-Byte-Schlüssel, der pro Nutzer lokal gespeichert wird. Die Erzeugung erfolgt in `src/services/deviceKeyService.ts` mit `crypto.getRandomValues`. Der Secret-Name ist `device-key:<userId>`.

```text
Generation -> Local Secret Store -> Unlock -> Argon2id -> HKDF mit Device Key
  -> finaler KDF output -> UserKey unwrap / Legacy-Key -> Encrypt/Decrypt
```

Aktuelle Vaults nutzen die UserKey-Schicht:

```text
Master-Passwort + Salt -> Argon2id
Argon2id output + Device Key -> HKDF-SHA-256("SINGRA_DEVICE_KEY_V1")
finaler KDF output -> HKDF("singra-vault-wrap-v1") -> WrapKey
WrapKey -> decrypt profiles.encrypted_user_key -> UserKey
UserKey -> decrypt/encrypt Vault Items, Kategorien, RSA/PQ Private Keys
```

Legacy-Vaults ohne `encrypted_user_key` verwenden den KDF-Output direkt als Vault-Key. Beim Aktivieren des Device Keys werden Legacy-Daten auf den Device-Key-geschützten Key umverschlüsselt. Bei UserKey-Vaults wird nur `encrypted_user_key` neu gewrappt; Vault-Items bleiben unter demselben zufälligen UserKey.

## Flüsse

| Bereich | Ist-Verhalten |
|---|---|
| Erzeugung | `generateDeviceKey()` erzeugt 32 Byte per CSPRNG. |
| Speicherung | Tauri: OS-Keychain via `keyring`; Web/PWA: IndexedDB + nicht-extrahierbarer WebCrypto-Wrapping-Key. |
| Laden | Web/PWA: `getDeviceKey(userId)` lädt aus dem Browser-Secret-Store und migriert alte IndexedDB-Device-Keys, falls möglich. Tauri: JS lädt kein Device-Key-Rohmaterial; Rust lädt intern aus `local-secret::device-key:<uuid>`. |
| Unlock | Web/PWA lädt den Device Key in JS und übergibt ihn an `deriveRawKey`. Tauri ruft `derive_device_protected_key` auf; Rust gibt nur den abgeleiteten KDF-Output zurück. |
| Vault-Key-Derivation | Browser: `deriveRawKey()` nutzt Argon2id und danach `deriveWithDeviceKey()` per HKDF-SHA-256. Tauri: Argon2id bleibt in JS, HKDF mit Device Key läuft in Rust mit `SINGRA_DEVICE_KEY_V1`. |
| Encryption/Decryption | Neue Daten werden mit `encryptionKey` verschlüsselt. Bei UserKey-Vaults ist das der entpackte UserKey. |
| Auto-Lock/Logout | `clearActiveVaultSession()` setzt CryptoKey und In-Memory-Device-Key zurück; Arrays werden best-effort genullt. |
| Gerätewechsel | Nur durch expliziten Import/Transfer des Device Keys. |
| Export | `sv-dk-transfer-v2` Envelope, Argon2id + AES-GCM, mit zufälligem Salt/IV. |
| Import | Decrypt + Länge prüfen + nur speichern, wenn noch kein Device Key vorhanden ist. Fehler überschreiben nichts. |
| Löschen | `deleteDeviceKey()` löscht aktuellen Local-Secret-Store und Legacy-IndexedDB-Record. |
| Recovery | Vault-Reset löscht Device Key lokal. Verlorener Device Key ohne Export macht geschützte Daten nicht entschlüsselbar. |

## Hauptfragen

| Frage | Ergebnis | Beweis |
|---|---|---|
| Wird der Device Key bei neuen Vaults erzeugt? | Nein, er ist optional und wird erst durch Settings-Aktivierung erzeugt. | `VaultContext.setupMasterPassword` erzeugt keinen Device Key; `enableDeviceKey` ruft `generateDeviceKey()`. |
| Wird er bei Unlock geladen? | Ja, wenn lokal vorhanden. | Web/PWA: `getRequiredDeviceKey()` -> `getResolvedDeviceKey()` -> `loadDeviceKey(user.id)`. Tauri: `getRequiredDeviceKey()` prüft Verfügbarkeit und `derive_device_protected_key` lädt intern aus der OS-Keychain. |
| Ist er für Decryption zwingend? | Für aktiv geschützte Vaults ja, weil Verifier/UserKey-Wrapper unter dem kombinierten KDF-Output liegt. | Tests in `deviceKeyService.test.ts` und `integration-crypto-pipeline.test.ts`. |
| Gibt es Master-only-Fallbacks? | Kein erfolgreicher Fallback für Device-Key-geschützte Vaults gefunden. Ohne lokalen Key versucht der Client ggf. Master-only, scheitert aber an Verifier/UserKey-Decrypt. | `deriveRawKey(..., deviceKey || undefined)` plus `verifyKey`/`unwrapUserKey`. |
| Gibt es alte Vaults ohne Device Key? | Ja, Device Key ist optional und abwärtskompatibel. | Doku und `enableDeviceKey` Legacy-Pfad. |
| Gibt es Migration/Flag? | Ja. | `profiles.vault_protection_mode` unterscheidet `master_only` und `device_key_required`; das Flag ist nicht sensitiv und enthält keinen Device-Key-Hash/Fingerprint. |
| Wird neue Encryption beachtet? | Ja, weil `encryptionKey` nach Unlock der passende UserKey/finale Key ist. | Encrypt-/Decrypt-Helper verwenden Context-`encryptionKey`. |
| Offline Snapshot | Speichert verschlüsselte Items und Unlock-Metadaten, aber keinen Device Key. | `offlineVaultService.ts` speichert Salt/Verifier/encryptedUserKey. |
| Export/Import | Device Key wird nur explizit und verschlüsselt exportiert/importiert. | `exportDeviceKeyForTransfer`, `importDeviceKeyFromTransfer`. |
| UserKey/RSA/PQ | Bei UserKey-Vaults schützt Device Key den UserKey-Wrapper; RSA/PQ private Keys sind anschließend unter UserKey geschützt. Legacy-Private-Key-Pfade nutzen teilweise Master-only bis zur Migration. | `unwrapUserKey`, `wrapPrivateKeyWithUserKey`, `migrateLegacyPrivateKeysToUserKey`. |

## Sicherheitsclaim

Der Claim "zusätzlicher 256-Bit-Schlüssel auf dem Gerät, der zusätzlich gegen Serverkompromittierung schützt" ist für Device-Key-geschützte Vaults fachlich korrekt, wenn er auf reine Serverkompromittierung begrenzt wird. Der Server erhält den Device Key nicht, und der finale KDF-Output ist ohne Device Key nicht ableitbar.

Der Claim ist nicht korrekt, wenn daraus Schutz gegen kompromittierte Browser-Laufzeit, XSS, Extensions, Malware oder einen kompromittierten Renderer abgeleitet wird. Web/PWA und Tauri/Desktop müssen getrennt beschrieben werden.

## Findings und Korrekturen

| ID | Severity | Bereich | Finding | Status |
|---|---|---|---|---|
| DK-2026-04-28-01 | P1 | Import | Valider Transfer eines falschen Device Keys konnte einen vorhandenen lokalen Device Key überschreiben. | Behoben: Import verweigert vorhandene lokale Keys. |
| DK-2026-04-28-02 | P1 | Validierung | `storeDeviceKey`/`deriveWithDeviceKey` validierten 32-Byte-Länge nicht hart genug. | Behoben: exakt 32 Byte erforderlich. |
| DK-2026-04-28-03 | P1 | Transfer-KDF | Envelope-Parameter waren nur nach unten begrenzt; extreme Werte konnten DoS auslösen. | Behoben: exakt erlaubte Argon2id-Parameter. |
| DK-2026-04-28-04 | P2 | Transfer UX | 12-Zeichen-Minimum war für abgefangene Offline-Envelopes zu schwach kommuniziert. | Behoben: Minimum 20, zufälliges Secret in UI. |
| DK-2026-04-28-05 | P2 | Aktivierung | Local-Secret-Store-Verfügbarkeit wurde nicht vor serverseitiger Device-Key-Aktivierung geprüft. | Behoben: Preflight vor Migration. |
| DK-2026-04-28-06 | P2 | UX/Architektur | Kein serverseitiges `device_key_required`-Flag; neues Gerät ohne Key bekommt ggf. generische Unlock-Fehler. | Behoben: `profiles.vault_protection_mode` + Unlock-Policy unterscheidet fehlenden lokalen Device Key von generischem Passwortfehler. |
| DK-2026-04-28-07 | P2 | Tauri | Tauri-Keychain-Commands lieferten den Device Key an den autorisierten JS-Renderer. | Behoben: generische `load_local_secret`-/`save_local_secret`-Zugriffe blockieren `device-key:<uuid>`; Rust-Commands erzeugen/derivieren/exportieren/importieren ohne Rohmaterial-Rückgabe. |

## Restrisiken

- Web/PWA ist keine OS-Keychain-Grenze.
- Transfer-Codes sind offline brute-forcebar, wenn das Transfer Secret schwach oder zusammen mit dem Code kompromittiert wird.
- JavaScript-Zeroization ist best-effort.
- Tauri reduziert die Exposition des langlebigen Device-Key-Rohmaterials gegenüber JS. Ein autorisierter kompromittierter Renderer kann weiterhin erlaubte Commands missbrauchen und nach erfolgreichem Unlock Vault-Daten im App-Kontext sehen; dies ist keine vollständige XSS-/Malware-Schutzgrenze.
