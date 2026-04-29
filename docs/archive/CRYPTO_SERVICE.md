# CryptoService — Verschlüsselungs-Engine

> **Datei:** `src/services/cryptoService.ts`  
> **Zweck:** Clientseitige Verschlüsselung der Vault-Payloads. Das Master-Passwort wird nicht serverseitig verarbeitet; Browser-/Renderer-Kompromittierung bleibt außerhalb dieser kryptografischen Grenze.

---

## Architektur-Überblick

```
Master-Passwort  ──►  Argon2id (KDF)  ──►  AES-256-GCM Key
                         ▲                        │
                     Salt (128 bit)          encrypt / decrypt
                    aus `profiles`                 │
                                              Vault-Daten
```

- **Key Derivation:** Argon2id via `hash-wasm`
- **Symmetric Encryption:** AES-256-GCM via Web Crypto API
- **Output-Format:** `base64( IV ‖ Ciphertext ‖ AuthTag )`

---

## Konstanten

| Konstante | Wert | Bedeutung |
|---|---|---|
| `KDF_PARAMS[1].memory` | 65 536 (64 MiB) | Legacy-RAM-Verbrauch für Argon2id |
| `KDF_PARAMS[2].memory` | 131 072 (128 MiB) | Aktueller RAM-Verbrauch für Argon2id |
| `ARGON2_ITERATIONS` | 3 | Anzahl Durchläufe |
| `ARGON2_PARALLELISM` | 4 | Parallele Lanes |
| `ARGON2_HASH_LENGTH` | 32 (256 Bit) | Schlüssellänge für AES-256 |
| `SALT_LENGTH` | 16 (128 Bit) | Zufälliger Salt |
| `IV_LENGTH` | 12 (96 Bit) | Standard-Nonce für AES-GCM |
| `TAG_LENGTH` | 128 (128 Bit) | Authentifizierungs-Tag |

---

## Funktionen

### `generateSalt(): string`

Erzeugt einen kryptographisch sicheren, zufälligen Salt.

**Ablauf:**
1. Generiert 16 zufällige Bytes via `crypto.getRandomValues()`
2. Konvertiert in Base64-String via `uint8ArrayToBase64()`

**Rückgabe:** Base64-kodierter Salt-String (128 Bit)

---

### `deriveKey(masterPassword, saltBase64): Promise<CryptoKey>`

Leitet einen AES-256-Schlüssel aus dem Master-Passwort ab.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `masterPassword` | `string` | Master-Passwort des Nutzers |
| `saltBase64` | `string` | Base64-Salt aus der `profiles`-Tabelle |

**Ablauf:**
1. Dekodiert den Base64-Salt in `Uint8Array`
2. Ruft `argon2id()` aus `hash-wasm` auf mit Konfiguration:
   - `parallelism: 4`, `iterations: 3`, `memorySize: 65536`, `hashLength: 32`
   - Output: Hex-String
3. Konvertiert den Hex-String in ein `Uint8Array` (32 Bytes)
4. Importiert die rohen Bytes als `CryptoKey` via `crypto.subtle.importKey()`:
   - Algorithmus: `AES-GCM`, Länge: 256
   - **Nicht extrahierbar** (`extractable: false`)
   - Erlaubte Operationen: `['encrypt', 'decrypt']`

**Rückgabe:** `CryptoKey` für AES-GCM-Operationen

> **Sicherheitshinweis:** Der Key wird nur im Speicher gehalten (über `VaultContext.encryptionKey`). Er wird nie persistiert.

---

### `encrypt(plaintext, key): Promise<string>`

Verschlüsselt Klartext-Daten mit AES-256-GCM.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `plaintext` | `string` | Zu verschlüsselnder Text |
| `key` | `CryptoKey` | Abgeleiteter Schlüssel |

**Ablauf:**
1. Generiert eine zufällige 12-Byte-IV via `crypto.getRandomValues()`
2. Kodiert den Plaintext als UTF-8 Bytes via `TextEncoder`
3. Verschlüsselt via `crypto.subtle.encrypt()` mit `AES-GCM`, `iv`, `tagLength: 128`
4. Kombiniert `IV + Ciphertext` (Ciphertext enthält bereits den AuthTag) in einem Uint8Array
5. Konvertiert das Ergebnis in Base64

**Rückgabe:** `base64( IV[12] ‖ Ciphertext ‖ AuthTag[16] )`

> **Wichtig:** Jede Verschlüsselung verwendet eine **neue, zufällige IV**. Gleicher Plaintext ergibt verschiedene Ciphertexte.

---

### `decrypt(encryptedBase64, key): Promise<string>`

Entschlüsselt AES-256-GCM-verschlüsselte Daten.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `encryptedBase64` | `string` | Base64-kodierter Ciphertext (IV + Daten + AuthTag) |
| `key` | `CryptoKey` | Abgeleiteter Schlüssel |

**Ablauf:**
1. Dekodiert den Base64-String in ein `Uint8Array`
2. Extrahiert die ersten 12 Bytes als IV
3. Der Rest ist Ciphertext (inkl. AuthTag)
4. Entschlüsselt via `crypto.subtle.decrypt()` mit `AES-GCM`
5. Dekodiert die Bytes als UTF-8 via `TextDecoder`

**Rückgabe:** Entschlüsselter Klartext-String

**Wirft:** `Error` bei falschem Schlüssel oder manipulierten Daten (AuthTag-Validierung schlägt fehl)

---

### `encryptVaultItem(data, key, entryId): Promise<string>`

Verschlüsselt die sensiblen Felder eines Vault-Eintrags.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `data` | `VaultItemData` | Objekt mit sensiblen Feldern |
| `key` | `CryptoKey` | Abgeleiteter Schlüssel |
| `entryId` | `string` | Vault-Item-ID für AAD-Bindung |

**Ablauf:**
1. Serialisiert `data` als JSON via `JSON.stringify()`
2. Verschlüsselt mit AES-GCM und bindet die Item-ID als Additional Authenticated Data (AAD)

**Rückgabe:** Versionierter Vault-Item-Ciphertext (`sv-vault-v1:...`)

---

### `decryptVaultItem(encryptedData, key, entryId): Promise<VaultItemData>`

Entschlüsselt die sensiblen Felder eines Vault-Eintrags.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `encryptedData` | `string` | Base64-kodierter, verschlüsselter JSON |
| `key` | `CryptoKey` | Abgeleiteter Schlüssel |
| `entryId` | `string` | Erwartete Vault-Item-ID für AAD-Prüfung |

**Ablauf:**
1. Prüft das versionierte Envelope-Format und entschlüsselt mit AAD-Bindung an `entryId`
2. Parst das Ergebnis als JSON via `JSON.parse()`

Legacy-No-AAD-Daten dürfen nur in expliziten Migrationspfaden gelesen werden. Normale Runtime-Lesewege sollen bei fehlender AAD-Bindung fehlschlagen, damit Ciphertexte nicht zwischen Items verschoben werden können.

**Rückgabe:** `VaultItemData`-Objekt

---

### `createVerificationHash(key): Promise<string>`

Erstellt einen Verifikations-Hash, um Unlock-Versuche zu prüfen, ohne das Passwort zu speichern.

**Ablauf:**
1. Verschlüsselt die Konstante `'SINGRA_VAULT_VERIFY_V3'` mit dem übergebenen Key und zufälliger IV
2. Gibt `v3:${encrypted}` zurück — kein Klartext in der DB
3. Das Ergebnis wird in der `profiles`-Tabelle als `master_password_verifier` gespeichert

**Rückgabe:** `v3:${encryptedConstant}`

> **Hinweis:** Ältere Verifier-Formate werden nur als Kompatibilitätspfad akzeptiert und sollen nach erfolgreichem Unlock migriert werden.

---

### `verifyKey(verificationHash, key): Promise<boolean>`

Prüft, ob ein Schlüssel korrekt ist.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `verificationHash` | `string` | Gespeicherter Verifier aus dem Profil |
| `key` | `CryptoKey` | Zu testender Schlüssel |

**Ablauf:**
1. Versucht, `verificationHash` mit `key` zu entschlüsseln
2. Vergleicht das Ergebnis mit der erwarteten Verifier-Konstante des jeweiligen Formats; aktuelle v3-Verifier nutzen `SINGRA_VAULT_VERIFY_V3`
3. Bei Entschlüsselungsfehler (falscher Key) → `catch` → `false`

**Rückgabe:** `true` wenn der Schlüssel korrekt ist

---

### `clearReferences(data): void`

Entfernt Referenzen auf sensible Daten aus einem VaultItemData-Objekt.

> ⚠️ **WARNING:** Diese Funktion löscht KEINEN Speicher sicher!
> JavaScript-Strings sind immutable. Es werden nur Referenzen entfernt,
> damit der GC die originalen Strings früher einsammeln kann.
> Für binäres Schlüsselmaterial stattdessen `Uint8Array.fill(0)` verwenden.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `data` | `VaultItemData` | Objekt mit sensiblen Daten |

**Ablauf:**
Setzt alle vorhandenen Felder auf leere Strings / Standardwerte:
- `title`, `websiteUrl`, `username`, `password`, `notes`, `totpSecret` → `''`
- `itemType` → `'password'`
- `isFavorite` → `false`
- `categoryId` → `null`
- `customFields` → alle Values auf `''`

> **Hinweis:** Der alte Name `secureClear` ist als deprecated Alias weiterhin verfügbar.

---

## Type: `VaultItemData`

```typescript
interface VaultItemData {
    title?: string;
    websiteUrl?: string;
    itemType?: 'password' | 'note' | 'totp' | 'card';
    isFavorite?: boolean;
    categoryId?: string | null;
    username?: string;
    password?: string;
    notes?: string;
    totpSecret?: string;
    customFields?: Record<string, string>;
}
```

Dies ist die Struktur, die als JSON verschlüsselt in der Spalte `encrypted_data` der Tabelle `vault_items` gespeichert wird.

---

## Hilfsfunktionen (intern, nicht exportiert)

### `uint8ArrayToBase64(bytes): string`
Konvertiert `Uint8Array` → Base64-String. Iteriert Byte für Byte und nutzt `btoa()`.

### `base64ToUint8Array(base64): string`
Konvertiert Base64-String → `Uint8Array`. Nutzt `atob()` und iteriert zeichenweise.
