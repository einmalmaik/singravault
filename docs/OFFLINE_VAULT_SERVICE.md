# OfflineVaultService — Offline-Vault-Cache & Sync

> **Datei:** `src/services/offlineVaultService.ts`  
> **Zweck:** Offline-First-Architektur mit IndexedDB-Cache und Mutation-Queue für lokale Änderungen, die bei Wiederverbindung synchronisiert werden.

---

## Architektur-Überblick

```
Online:   Supabase ──► fetchRemoteOfflineSnapshot() ──► IndexedDB (Snapshot)
                                                              ▲
Offline:  Lokale Änderungen ──► enqueueOfflineMutation()     │
                                       │                      │
                                       ▼                      │
                               IndexedDB (Mutations)          │
                                       │                      │
Online:   syncOfflineMutations() ──────┴───── Replay → Supabase
```

**IndexedDB-Datenbank:** `singra-offline-vault` (Version 1)

| Object Store | Key | Zweck |
|---|---|---|
| `snapshots` | `userId` | Vault-Snapshots pro Nutzer |
| `mutations` | `id` (UUID) | Warteschlange ausstehender Änderungen |

---

## Types

### `OfflineVaultSnapshot`
```typescript
interface OfflineVaultSnapshot {
    userId: string;
    vaultId: string | null;
    items: VaultItemRow[];
    categories: CategoryRow[];
    lastSyncedAt: string | null;
    updatedAt: string;
    encryptionSalt?: string | null;       // für Offline-Unlock
    masterPasswordVerifier?: string | null; // für Offline-Unlock
    kdfVersion?: number | null;            // KDF-Version für korrekte Key-Ableitung offline
}
```

### `OfflineMutation` (Union-Typ)
Vier Varianten: `upsert_item`, `delete_item`, `upsert_category`, `delete_category`  
Jede enthält: `id` (UUID), `userId`, `createdAt`, `type`, `payload`

---

## Offline-Unlock-Flow (seit Feb 2026)

```text
1. isAppOnline() prüfen
2. Offline? → getOfflineCredentials() → salt/verifier/kdfVersion setzen → Unlock-Screen
3. Online? → Supabase-Query → Profil laden → Credentials + kdfVersion cachen
4. Fehler (beliebig)? → Cache versuchen → Kein Cache? → Setup-Screen
```

**Wichtig:** `kdfVersion` wird mitgecacht, damit offline die korrekte KDF (Argon2id mit den richtigen Parametern) verwendet wird. Ohne den gecachten `kdfVersion` würde der Default `1` greifen und eine falsche Key-Ableitung erzeugen.

---

## Funktionen

### Netzwerk-Erkennung

#### `isAppOnline(): boolean`
Prüft `navigator.onLine`. Gibt `true` zurück wenn `navigator` nicht verfügbar (SSR).

#### `isLikelyOfflineError(error): boolean`
Erkennt Netzwerk-Fehler anhand der Fehlermeldung.

**Geprüfte Muster:** `'failed to fetch'`, `'network'`, `'fetch'`, `'load failed'`, `'xhr'`

---

### Snapshot-Verwaltung

#### `getOfflineSnapshot(userId): Promise<OfflineVaultSnapshot | null>`
Liest den Snapshot aus IndexedDB für den gegebenen User.

#### `saveOfflineSnapshot(snapshot): Promise<void>`
Speichert/überschreibt einen Snapshot in IndexedDB.

#### `saveOfflineCredentials(userId, encryptionSalt, masterPasswordVerifier, kdfVersion?): Promise<void>`
Speichert Verschlüsselungs-Credentials für den Offline-Unlock.

**Parameter:**
- `userId` — Benutzer-ID
- `encryptionSalt` — Salt für die Key-Ableitung
- `masterPasswordVerifier` — Hash zur Passwort-Verifikation
- `kdfVersion` (optional) — KDF-Version (z.B. 2 für Argon2id mit aktuellen Parametern)

#### `getOfflineCredentials(userId): Promise<{ salt, verifier, kdfVersion } | null>`
Liest gecachete Credentials für den Offline-Unlock. Gibt jetzt auch `kdfVersion` zurück (`null` falls nicht gecacht).

---

### Item- und Kategorie-Verwaltung (lokal)

#### `upsertOfflineItemRow(userId, row, vaultIdOverride?): Promise<void>`
Fügt ein Item zum lokalen Snapshot hinzu oder aktualisiert es.

#### `removeOfflineItemRow(userId, itemId): Promise<void>`
Entfernt ein Item aus dem lokalen Snapshot.

#### `upsertOfflineCategoryRow(userId, row): Promise<void>`
Fügt eine Kategorie zum lokalen Snapshot hinzu/aktualisiert sie.

#### `removeOfflineCategoryRow(userId, categoryId): Promise<void>`
Entfernt eine Kategorie aus dem lokalen Snapshot.

---

### Mutation-Queue

#### `enqueueOfflineMutation(mutation): Promise<string>`
Reiht eine Offline-Mutation in die Warteschlange ein.

#### `getOfflineMutations(userId): Promise<OfflineMutation[]>`
Liest alle ausstehenden Mutationen für einen User, **sortiert nach `createdAt`**.

#### `removeOfflineMutations(mutationIds): Promise<void>`
Löscht erfolgreich verarbeitete Mutationen aus der Queue.

---

### Remote-Sync

#### `fetchRemoteOfflineSnapshot(userId): Promise<OfflineVaultSnapshot>`
Lädt den kompletten Vault vom Server und speichert ihn als lokalen Snapshot.

#### `loadVaultSnapshot(userId): Promise<{ snapshot, source }>`
Intelligentes Laden: Online → Remote, Fehler → Cache, kein Cache → Empty.

#### `syncOfflineMutations(userId): Promise<{ processed, remaining, errors }>`
Spielt die Mutation-Queue gegen den Server ab.
