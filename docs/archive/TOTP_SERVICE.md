# TOTPService — Time-based One-Time Password

> **Datei:** `src/services/totpService.ts`  
> **Zweck:** Generierung und Verwaltung von TOTP-Codes nach RFC 6238 für gespeicherte Vault-Einträge vom Typ `totp`.

---

## Abhängigkeit

Nutzt die Bibliothek **`otpauth`** (`OTPAuth.TOTP`, `OTPAuth.Secret`).

---

## Funktionen

### `generateTOTP(secret): string`

Generiert den aktuellen 6-stelligen TOTP-Code.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `secret` | `string` | Base32-kodiertes TOTP-Geheimnis |

**Ablauf:**
1. Bereinigt das Secret: Leerzeichen entfernen, Uppercase
2. Erstellt ein `OTPAuth.TOTP`-Objekt mit:
   - `issuer: 'Singra Vault'`
   - `algorithm: 'SHA1'`
   - `digits: 6`
   - `period: 30` (Sekunden)
   - `secret`: via `OTPAuth.Secret.fromBase32()`
3. Ruft `totp.generate()` auf

**Rückgabe:** 6-stelliger Code als String (z.B. `'482301'`)  
**Fehlerfall:** Gibt `'------'` zurück und loggt Fehler in die Konsole.

---

### `getTimeRemaining(): number`

Berechnet die verbleibenden Sekunden bis zum nächsten TOTP-Wechsel.

**Ablauf:**
1. `now = floor(Date.now() / 1000)` (Unix-Sekunden)
2. `remaining = 30 - (now % 30)`

**Rückgabe:** Zahl zwischen 1 und 30

---

### `isValidTOTPSecret(secret): boolean`

Validiert ein TOTP-Geheimnis auf korrektes Format.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `secret` | `string` | Zu validierendes Secret |

**Ablauf:**
1. Bereinigt: Leerzeichen entfernen, Uppercase
2. Prüft gegen Base32-RegEx: `/^[A-Z2-7]+=*$/`
3. Prüft Mindestlänge: ≥ 16 Zeichen

**Rückgabe:** `true` wenn valide

---

### `formatTOTPCode(code): string`

Formatiert einen 6-stelligen Code für die Anzeige.

**Ablauf:**
- Wenn Länge ≠ 6 → gibt `code` unverändert zurück
- Sonst: `"123 456"` (Leerzeichen in der Mitte)

**Rückgabe:** Formatierter Code-String

---

### `parseTOTPUri(uri): TOTPData | null`

Parst eine TOTP-URI (aus QR-Codes) und extrahiert die Konfiguration.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `uri` | `string` | `otpauth://totp/...` URI |

**Ablauf:**
1. Parst die URI als `new URL(uri)`
2. Prüft: `protocol === 'otpauth:'` und `host === 'totp'`
3. Extrahiert:
   - `secret` aus Query-Parameter (→ Uppercase)
   - `label` aus Pfad (URL-dekodiert)
   - `issuer` aus Query-Parameter (Fallback: `''`)
   - `algorithm` (Fallback: `'SHA1'`)
   - `digits` (Fallback: `6`)
   - `period` (Fallback: `30`)

**Rückgabe:** `TOTPData`-Objekt oder `null` bei ungültigem Format

---

### `generateTOTPUri(data): string`

Generiert eine `otpauth://`-URI für QR-Code-Anzeige.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `data` | `TOTPData` | TOTP-Konfigurationsdaten |

**Ablauf:**
1. Erstellt ein `OTPAuth.TOTP`-Objekt aus den `data`-Feldern
2. Ruft `totp.toString()` auf

**Rückgabe:** Vollständige `otpauth://totp/...` URI

---

## Type: `TOTPData`

```typescript
interface TOTPData {
    secret: string;      // Base32-kodiertes Geheimnis
    label: string;       // Konto-Bezeichnung
    issuer: string;      // Dienstanbieter
    algorithm?: string;  // Standard: 'SHA1'
    digits?: number;     // Standard: 6
    period?: number;     // Standard: 30
}
```
