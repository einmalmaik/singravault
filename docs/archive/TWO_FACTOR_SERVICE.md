# TwoFactorService — Zwei-Faktor-Authentifizierung

> **Datei:** `src/services/twoFactorService.ts`  
> **Zweck:** Vollständiger Lebenszyklus der TOTP-basierten 2FA: Setup, Aktivierung, Verifizierung, Backup-Codes, Deaktivierung.

---

## Architektur-Überblick

```
Setup → QR-Code/Secret anzeigen → Code verifizieren → Backup-Codes speichern → 2FA aktiv
                                                                                    │
                                    ┌───────────────────────────────────────────────┘
                                    ▼
                           Login / Vault-Unlock
                           ├── TOTP-Code verifizieren
                           └── Backup-Code verifizieren (einmalig, wird markiert)
```

**Datenbank-Tabellen:**
- `user_2fa` — Speichert Secret (verschlüsselt via RPC), `is_enabled`, `vault_2fa_enabled`, `last_verified_at`
- `backup_codes` — Gespeicherte SHA-256-Hashes der Backup-Codes, `is_used`-Flag

---

## Konstanten

| Konstante | Wert | Bedeutung |
|---|---|---|
| `ISSUER` | `'Singra Vault'` | Anzeigename in Authenticator-Apps |
| `BACKUP_CODE_COUNT` | `5` | Anzahl generierter Backup-Codes |
| `BACKUP_CODE_LENGTH` | `8` | Zeichen pro Backup-Code |

---

## Funktionen

### Secret-Generierung

#### `generateTOTPSecret(): string`
Erzeugt ein neues 160-Bit TOTP-Secret.

**Ablauf:** `new OTPAuth.Secret({ size: 20 })` → `.base32`

**Rückgabe:** Base32-kodierter Secret-String

---

#### `generateQRCodeUri(secret, email): string`
Erzeugt die `otpauth://` URI für Authenticator-Apps.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `secret` | `string` | Base32 Secret |
| `email` | `string` | E-Mail des Nutzers (als Label) |

**Ablauf:** Erstellt `OTPAuth.TOTP` mit `issuer: 'Singra Vault'`, `SHA1`, `6 digits`, `30s period` → `.toString()`

---

#### `formatSecretForDisplay(secret): string`
Formatiert Secret für die manuelle Eingabe.

**Ablauf:** Teilt den String in 4er-Gruppen mit Leerzeichen: `JBSW Y3DP EHPK 3PXP`

---

### TOTP-Verifizierung

#### `verifyTOTPCode(secret, code): boolean`
Verifiziert einen 6-stelligen TOTP-Code.

**Parameter:**
| Param | Typ | Beschreibung |
|---|---|---|
| `secret` | `string` | Base32 Secret (Leerzeichen werden entfernt) |
| `code` | `string` | Eingegebener 6-stelliger Code (Leerzeichen werden entfernt) |

**Ablauf:**
1. Erstellt `OTPAuth.TOTP` mit dem Secret
2. Ruft `totp.validate({ token: code, window: 1 })` auf
   - `window: 1` → erlaubt **±1 Periode** (30 Sekunden) Toleranz für Uhrenabweichung
3. `delta !== null` → Code ist gültig

**Rückgabe:** `true` wenn der Code gültig ist

---

### Backup-Codes

#### `generateBackupCodes(): string[]`
Generiert 5 zufällige Backup-Codes.

**Ablauf:**
1. Zeichensatz: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (ohne `0`, `O`, `1`, `I` um Verwechslungen zu vermeiden)
2. Für jeden Code: 8 zufällige Zeichen via `Math.random()` (⚠️ **nicht** kryptographisch sicher)
3. Formatierung als `XXXX-XXXX`

**Rückgabe:** Array von 5 Codes (z.B. `['ABCD-EF23', 'GH56-JKLM', ...]`)

> **Hinweis:** Die Codes werden als Klartext dem Nutzer angezeigt, aber **gehasht** in der DB gespeichert.

---

#### `hashBackupCode(code): Promise<string>`
Hasht einen Backup-Code für sichere Speicherung.

**Ablauf:**
1. Normalisiert: Bindestriche entfernen, Uppercase
2. Kodiert als UTF-8 Bytes
3. `crypto.subtle.digest('SHA-256', data)`
4. Konvertiert Hash-Bytes zu Hex-String

**Rückgabe:** SHA-256-Hash als Hex-String

---

### Datenbank-Operationen

#### `get2FAStatus(userId): Promise<TwoFactorStatus | null>`

Ruft den aktuellen 2FA-Status eines Nutzers ab.

**Ablauf:**
1. Liest `user_2fa` Tabelle: `is_enabled`, `vault_2fa_enabled`, `last_verified_at`
2. Zählt verbleibende, ungebrauchte Backup-Codes aus `backup_codes`

**Rückgabe:**
```typescript
interface TwoFactorStatus {
    isEnabled: boolean;
    vaultTwoFactorEnabled: boolean;
    lastVerifiedAt: string | null;
    backupCodesRemaining: number;
}
```

---

#### `getTOTPSecret(userId): Promise<string | null>`

Ruft das TOTP-Secret über eine **Supabase RPC-Funktion** ab.

**Ablauf:** Ruft `supabase.rpc('get_user_2fa_secret', { p_user_id, p_require_enabled: true })` auf.  
**Sicherheit:** Die RPC-Funktion kapselt den Zugriff auf das Secret serverseitig.

---

#### `initializeTwoFactorSetup(userId, secret): Promise<{ success, error? }>`

Initialisiert die 2FA-Einrichtung (speichert Secret, aktiviert noch nicht).

**Ablauf:** Ruft `supabase.rpc('initialize_user_2fa_secret', { p_user_id, p_secret })` auf.

---

#### `enableTwoFactor(userId, code, backupCodes): Promise<{ success, error? }>`

Aktiviert 2FA nach erfolgreicher Code-Verifizierung.

**Ablauf:**
1. Holt das **ausstehende** Secret via `get_user_2fa_secret` mit `p_require_enabled: false`
2. Verifiziert den TOTP-Code gegen das Secret
3. Setzt `is_enabled: true`, `enabled_at` und `last_verified_at` in `user_2fa`
4. Hasht alle Backup-Codes via `hashBackupCode()` und speichert sie in `backup_codes`

**Sicherheit:** 2FA wird erst aktiviert, wenn der Nutzer beweist, dass sein Authenticator funktioniert.

---

#### `verifyAndConsumeBackupCode(userId, code): Promise<boolean>`

Verifiziert einen Backup-Code und markiert ihn als verbraucht.

**Ablauf:**
1. Hasht den eingegebenen Code via `hashBackupCode()`
2. Sucht in `backup_codes` nach: `user_id` + `code_hash` + `is_used: false`
3. Markiert den gefundenen Code als `is_used: true`, `used_at: now()`
4. Aktualisiert `last_verified_at` in `user_2fa`

**Rückgabe:** `true` wenn ein gültiger, unbenutzter Code gefunden wurde

---

#### `disableTwoFactor(userId, code): Promise<{ success, error? }>`

Deaktiviert 2FA (erfordert gültigen TOTP-Code).

**Ablauf:**
1. Holt das aktive Secret
2. Verifiziert den TOTP-Code (**Backup-Codes sind NICHT erlaubt** zum Deaktivieren)
3. Löscht den Eintrag aus `user_2fa`
4. Löscht alle `backup_codes` des Nutzers

---

#### `setVaultTwoFactor(userId, enabled): Promise<{ success, error? }>`

Schaltet die Vault-2FA-Anforderung um.

**Ablauf:** Aktualisiert `vault_2fa_enabled` in `user_2fa` (nur wenn 2FA `is_enabled: true`).

**Effekt:** Wenn aktiv, muss beim Vault-Unlock zusätzlich zum Master-Passwort ein 2FA-Code eingegeben werden.

---

#### `regenerateBackupCodes(userId): Promise<{ success, codes?, error? }>`

Generiert neue Backup-Codes und löscht die alten.

**Ablauf:**
1. Prüft ob 2FA aktiviert ist
2. Löscht alle existierenden `backup_codes`
3. Generiert 5 neue Codes via `generateBackupCodes()`
4. Hasht und speichert die neuen Codes

**Rückgabe:** Die neuen Klartext-Codes (für den Nutzer zum Notieren)

---

#### `verifyTwoFactorForLogin(userId, code, isBackupCode): Promise<boolean>`

Verifiziert 2FA beim Login (TOTP oder Backup-Code).

**Ablauf:**
1. Wenn `isBackupCode: true` → delegiert an `verifyAndConsumeBackupCode()`
2. Sonst → holt Secret, ruft `verifyTOTPCode()` auf
3. Bei Erfolg → aktualisiert `last_verified_at`

**Rückgabe:** `true` wenn Verifizierung erfolgreich
