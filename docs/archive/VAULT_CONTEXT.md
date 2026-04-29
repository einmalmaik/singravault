# VaultContext — Vault-Zustandsverwaltung

> **Datei:** `src/contexts/VaultContext.tsx`  
> **Zweck:** Zentraler Kontext für den Vault-Zustand: Lock/Unlock-Status, Master-Passwort-Setup, abgeleiteter Verschlüsselungsschlüssel, Auto-Lock-Timer, und Verschlüsselungs-/Entschlüsselungs-Helper.

---

## Context-Interface

```typescript
interface VaultContextType {
    isLocked: boolean;                    // Vault gesperrt?
    hasMasterPassword: boolean;           // Encryption-Salt existiert?
    isLoading: boolean;                   // Wird initialisiert?
    encryptionKey: CryptoKey | null;      // Abgeleiteter AES-256-Schlüssel (nur im RAM)
    pendingSessionRestore: boolean;       // Session-Wiederherstellung ausstehend?
    autoLockTimeout: number;              // Auto-Lock-Timer in MS
    
    // Aktionen
    setupMasterPassword: (password) => Promise<{ error? }>;
    unlock: (password) => Promise<{ error? }>;
    lock: () => void;
    setAutoLockTimeout: (ms) => void;
    encryptData: (plaintext) => Promise<string>;
    decryptData: (encrypted) => Promise<string>;
    encryptVaultItem: (data) => Promise<string>;
    decryptVaultItem: (encrypted) => Promise<VaultItemData>;
}
```

---

## Initialisierung

### `checkMasterPasswordStatus()` (useEffect)

Wird ausgelöst wenn `user` sich ändert (Login, Logout).

**Ablauf:**
1. Kein User → setzt alles auf Standardwerte zurück
2. Liest `profiles` Tabelle: `encryption_salt`
3. **Kein Salt vorhanden** → `hasMasterPassword: false` (Setup-Flow anzeigen)
4. **Salt vorhanden:**
   - `hasMasterPassword: true`
   - Prüft ob eine Session in `sessionStorage` existiert (Key: `singra_vault_session`)
   - **Session gefunden:** Setzt `pendingSessionRestore: true` (Nutzer muss Passwort erneut eingeben)
   - **Keine Session:** `isLocked: true`

> **Session-Strategie:** Die Session speichert nur einen Marker − nie den Schlüssel. Bei Tab-Schließung wird `sessionStorage` automatisch gelöscht.

---

## Master-Passwort-Setup

### `setupMasterPassword(password): Promise<{ error? }>`

Richtet das Master-Passwort beim ersten Mal ein.

**Ablauf:**
1. Generiert einen neuen Salt via `generateSalt()`
2. Leitet einen AES-256-Schlüssel ab via `deriveKey(password, salt)`
3. Erstellt einen Verifikations-Hash via `createVerificationHash(key)`
4. Speichert `encryption_salt` und `master_password_verifier` in `profiles`
5. Setzt `encryptionKey` im State
6. Speichert Session in `sessionStorage`
7. Speichert Offline-Credentials via `saveOfflineCredentials()`
8. Entriegelt den Vault: `isLocked: false`, `hasMasterPassword: true`

---

## Unlock

### `unlock(password): Promise<{ error? }>`

Entsperrt den Vault mit dem Master-Passwort.

**Ablauf:**
1. Liest `encryption_salt` und `master_password_verifier` aus `profiles`
   - **Online:** Fragt Supabase
   - **Offline-Fallback:** Nutzt gecachete Credentials aus IndexedDB
2. Leitet den Key ab via `deriveKey(password, salt)`
3. Verifiziert via `verifyKey(verifier, key)`
4. Bei Erfolg:
   - Setzt `encryptionKey` im State
   - Speichert Session in `sessionStorage`
   - Speichert Offline-Credentials
   - `isLocked: false`

> **Sicherheit:** Der `CryptoKey` ist `extractable: false` und existiert nur im RAM. Er kann nicht serialisiert werden.

---

## Lock

### `lock(): void`

Sperrt den Vault sofort.

**Ablauf:**
1. `encryptionKey: null` (GC kann den Key freigeben)
2. `isLocked: true`
3. Entfernt `singra_vault_session` aus `sessionStorage`

---

## Auto-Lock

### Auto-Lock-Timer (useEffect)

**Ablauf:**
1. Wird aktiviert wenn: `!isLocked && autoLockTimeout > 0`
2. Erstellt `setInterval()` mit Prüfung alle 5 Sekunden
3. Trackt letzte Aktivität via globalem `mousemove`/`keydown`/`mousedown`/`touchstart` Listener
4. Wenn `Date.now() - lastActivity > autoLockTimeout` → `lock()`
5. **Cleanup:** Entfernt Listener und Interval bei Unmount

### `setAutoLockTimeout(ms): void`
Setzt den Timeout-Wert. `0` deaktiviert Auto-Lock.

---

## Verschlüsselungs-Helper

### `encryptData(plaintext): Promise<string>`
Wrapper für `encrypt(plaintext, encryptionKey)`. Wirft wenn kein Key vorhanden.

### `decryptData(encrypted): Promise<string>`
Wrapper für `decrypt(encrypted, encryptionKey)`. Wirft wenn kein Key vorhanden.

### `encryptVaultItem(data): Promise<string>`
Wrapper für `encryptVaultItem(data, encryptionKey)`. Wirft wenn kein Key vorhanden.

### `decryptVaultItem(encrypted): Promise<VaultItemData>`
Wrapper für `decryptVaultItem(encrypted, encryptionKey)`. Wirft wenn kein Key vorhanden.

---

## Hook: `useVault()`

```typescript
export function useVault(): VaultContextType
```

Zugriff auf den Vault-Kontext. Wirft `Error` wenn außerhalb des `VaultProvider` verwendet.

---

## Sicherheits-Architektur

| Aspekt | Implementierung |
|---|---|
| Schlüssel-Speicherung | Nur im RAM (`CryptoKey` State) |
| Session-Persistenz | `sessionStorage` (stirbt mit Tab) |
| Auto-Lock | Konfigurierbarer Inaktivitäts-Timer |
| Offline-Unlock | Credentials in IndexedDB gecached |
| Key Extraction | `extractable: false` bei Import |
