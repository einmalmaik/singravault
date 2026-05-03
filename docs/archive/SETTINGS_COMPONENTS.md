# Settings-Komponenten — Einstellungen

> **Dateien:**  
> `src/components/settings/SecuritySettings.tsx`  
> `src/components/settings/TwoFactorSettings.tsx`  
> `src/components/settings/DataSettings.tsx`

---

## SecuritySettings

> **Datei:** `src/components/settings/SecuritySettings.tsx`

Sicherheitseinstellungen: Auto-Lock-Timer und manuelles Sperren.

### Auto-Lock-Optionen

| Wert (ms) | Anzeige |
|---|---|
| `60000` | 1 min |
| `300000` | 5 min |
| `900000` | 15 min |
| `1800000` | 30 min |
| `3600000` | 1 h |
| `0` | Nie |

### `handleAutoLockChange(value: string)`

**Ablauf:**
1. Parst den String zu `number`
2. Ruft `setAutoLockTimeout()` aus `VaultContext` auf
3. Persistiert in `localStorage` unter `singra_autolock`
4. Zeigt Erfolgs-Toast an

### `handleLockNow()`

**Ablauf:**
1. Ruft `lock()` aus `VaultContext` auf
2. Zeigt Toast „Vault gesperrt" an
3. Navigiert zu `/vault` mit `replace: true` (kein Zurück-Button)

### Rendering
- Auto-Lock Select-Dropdown
- Manuelles Sperren-Button (disabled wenn bereits gesperrt)
- Rendert `<TwoFactorSettings />` darunter (separiert durch `<Separator>`)

---

## TwoFactorSettings

> **Datei:** `src/components/settings/TwoFactorSettings.tsx`

Multi-Step-Setup-Flow für 2FA-Einrichtung.

### Setup-Schritte

```typescript
type SetupStep = 'idle' | 'qr' | 'verify' | 'backup' | 'complete';
```

| Schritt | Anzeige |
|---|---|
| `idle` | Status-Karte (2FA ein/aus, Optionen) |
| `qr` | QR-Code und manuelles Secret |
| `verify` | Code-Eingabefeld (6-stellig) |
| `backup` | Backup-Codes-Anzeige + Download |
| `complete` | Erfolgsmeldung |

### State
| State | Typ | Zweck |
|---|---|---|
| `status` | `TwoFactorStatus \| null` | Aktueller 2FA-Status |
| `setupStep` | `SetupStep` | Aktueller Setup-Schritt |
| `secret` | `string` | Generiertes TOTP-Secret |
| `qrUri` | `string` | QR-Code URI |
| `verificationCode` | `string` | Eingegebener Code |
| `backupCodes` | `string[]` | Generierte Backup-Codes |

### `loadStatus()` (useEffect)
Lädt den 2FA-Status via `get2FAStatus(userId)` bei Mount und nach Änderungen.

### `startSetup()`

**Ablauf:**
1. Generiert Secret via `generateTOTPSecret()`
2. Generiert QR-URI via `generateQRCodeUri(secret, email)`
3. Generiert Backup-Codes via `generateBackupCodes()`
4. Initialisiert Setup in DB via `initializeTwoFactorSetup(userId, secret)`
5. Wechselt zu Schritt `'qr'`

### `handleVerify()`

**Ablauf:**
1. Validiert den eingegebenen 6-stelligen Code
2. Ruft `enableTwoFactor(userId, code, backupCodes)` auf
3. Bei Erfolg → Schritt `'backup'`
4. Bei Fehler → Toast mit Fehlermeldung

### `handleCodeInput(value: string)`

**Ablauf:**
1. Erlaubt nur Ziffern, max. 6 Zeichen
2. **Auto-Submit:** Wenn Länge 6 erreicht → ruft `handleVerify()` automatisch auf

### `downloadBackupCodes()`

**Ablauf:**
1. Erstellt Textdatei-Inhalt mit Header und allen Codes
2. Erstellt Blob → `URL.createObjectURL()`
3. Triggert Download als `singra-backup-codes.txt`

### `copySecret()`
Kopiert das formatierte Secret in die Zwischenablage.

### `handleDisable()`

**Ablauf:**
1. Prüft ob Bestätigungscode eingegeben wurde
2. Ruft `disableTwoFactor(userId, code)` auf
3. Lädt Status neu, kehrt zu `'idle'` zurück

### `handleVaultToggle(enabled: boolean)`

**Ablauf:**
1. Ruft `setVaultTwoFactor(userId, enabled)` auf
2. Lädt Status neu
3. Zeigt Erfolgs-Toast an

### `handleRegenerateBackupCodes()`

**Ablauf:**
1. Ruft `regenerateBackupCodes(userId)` auf
2. Speichert neue Codes im State
3. Wechselt zu Schritt `'backup'` um die neuen Codes anzuzeigen

### `completeSetup()`
Setzt Setup zurück zu `'idle'`, lädt Status neu.

---

## DataSettings

> **Datei:** `src/components/settings/DataSettings.tsx`

Export- und Import-Funktionalität für Vault-Daten.

### `handleExport()`

Exportiert alle Vault-Daten als JSON-Datei.

**Ablauf:**
1. Prüft ob Verschlüsselungsschlüssel vorhanden ist
2. Liest alle Items aus `vault_items` via Supabase
3. Liest alle Kategorien aus `categories` via Supabase
4. **Entschlüsselung aller Items:**
   - Für jedes Item: `decryptVaultItem(encrypted_data)`
   - Bei Fehler → Placeholder `'Encrypted Item'`
5. **Entschlüsselung aller Kategorienamen:**
   - Prüft auf `enc:cat:v1:` Prefix → `decryptData()`
6. Baut Export-Objekt:
   ```json
   {
       "version": 1,
       "exportedAt": "ISO-Timestamp",
       "items": [...],
       "categories": [...]
   }
   ```
7. Erstellt JSON-Blob → Download als `singra-vault-export-{timestamp}.json`

### `handleFileSelect(e)`

Dateiauswahl-Handler für die Import-Funktion.

**Ablauf:** Liest die ausgewählte Datei via `FileReader.readAsText()` → speichert im State.

### `handleImport()`

Importiert Vault-Daten aus einer JSON-Datei.

**Ablauf:**
1. Parst JSON und validiert `version: 1`
2. Ermittelt die Vault-ID via `resolveDefaultVaultId()`
3. **Kategorien importieren:**
   - Für jede Kategorie: Verschlüsselt Namen → `enc:cat:v1:` Prefix
   - Prüft via Supabase ob Kategorie bereits existiert (Duplikat-Check per Name)
   - Erstellt neue Kategorien oder nutzt existierende IDs
   - Baut ein Mapping: `alte_id → neue_id`
4. **Items importieren:**
   - Für jedes Item: Baut `VaultItemData` aus den Import-Daten
   - Verschlüsselt via `encryptVaultItem()`
   - Mapped Kategorie-IDs auf neue
   - Inserted in `vault_items`
5. Zeigt Erfolgs-Toast mit Anzahl importierter Items an

> **Wichtig:** Beim Import werden alle sensiblen Daten **neu verschlüsselt** mit dem aktuellen Encryption-Key. Das erlaubt Import von Backups auch mit neuem Master-Passwort.
