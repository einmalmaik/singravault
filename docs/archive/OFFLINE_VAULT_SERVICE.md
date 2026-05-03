# OfflineVaultService - Offline-Vault-Cache, Sync und Rollback-Grenzen

> **Datei:** `src/services/offlineVaultService.ts`  
> **Zweck:** lokaler IndexedDB-Cache, Offline-Unlock-Metadaten und Mutation-Queue für Änderungen, die nach Wiederverbindung kontrolliert synchronisiert werden.

## Architektur-Überblick

```text
Online:   Supabase -> fetchRemoteOfflineSnapshot() -> IndexedDB snapshot
                         |                                 ^
                         | get_vault_sync_head()           |
                         v                                 |
                    remoteRevision ------------------------+

Offline:  local change -> enqueueOfflineMutation(baseRemoteRevision)
                         -> IndexedDB mutations

Online:   syncOfflineMutations()
          -> apply_vault_mutation(baseRemoteRevision, type, payload)
          -> remove only successfully applied mutations
```

**IndexedDB-Datenbank:** `singra-offline-vault` (Version 2)

| Object Store | Key | Zweck |
|---|---|---|
| `snapshots` | `userId` | Vault-Snapshot pro Nutzer |
| `mutations` | `id` (UUID) | Warteschlange ausstehender Änderungen |

## Sicherheitsgrenze

Der Offline-Cache ist ein lokaler Verfügbarkeits- und Komfortpfad. Er ist keine stärkere Secret Boundary als die jeweilige Plattform zulässt:

- Im Browser/PWA liegt der Cache im Same-Origin-Browser-Speicher. XSS oder kompromittiertes Same-Origin-JavaScript ist deshalb als Vault-Compromise-Szenario zu behandeln, sobald der Vault entsperrt ist.
- Auf Tauri/Desktop kann lokales Secret-Material über den Rust-Layer an OS-Secret-Storage gebunden werden; das ist stärker als Browser-IndexedDB, aber kein Schutz gegen Malware mit Zugriff auf den entsperrten Prozess.
- Ein frisches Gerät ohne lokale High-Water-Mark kann einen alten, intern konsistenten Serverstand nicht allein kryptografisch als Rollback erkennen.

## Datenmodell

### `OfflineVaultSnapshot`

```typescript
interface OfflineVaultSnapshot {
    userId: string;
    vaultId: string | null;
    items: VaultItemRow[];
    categories: CategoryRow[];
    lastSyncedAt: string | null;
    updatedAt: string;
    encryptionSalt?: string | null;
    masterPasswordVerifier?: string | null;
    kdfVersion?: number | null;
    remoteRevision?: number | null;
}
```

`remoteRevision` ist die zuletzt akzeptierte serverseitige Vault-Revision. Beim Laden eines neuen Remote-Snapshots darf diese Revision nicht kleiner werden. Ein kleinerer Wert wird als Rollback/stale Snapshot behandelt und überschreibt den lokalen Cache nicht.

### `OfflineMutation`

Die Queue enthält vier Varianten: `upsert_item`, `delete_item`, `upsert_category`, `delete_category`.

Jede Mutation enthält `id`, `userId`, `createdAt`, `type`, `payload` und optional `baseRemoteRevision`. Beim Enqueue wird `baseRemoteRevision` aus dem aktuellen Snapshot übernommen, sofern der Aufrufer keinen Wert setzt.

## Serverseitige Revisionen

Die Migration `20260427212000_harden_emergency_access_and_sync_heads.sql` führt `vault_sync_heads` ein:

- `vault_id` identifiziert den Vault.
- `revision` ist ein monoton erhöhter Zähler.
- Trigger auf `vault_items` und `categories` erhöhen die Revision bei Insert/Update/Delete.
- `get_vault_sync_head(p_vault_id)` liefert die aktuelle Revision für den authentifizierten Vault-Besitzer.
- `apply_vault_mutation(p_base_revision, p_type, p_payload)` führt Offline-Mutationen als Compare-and-Swap aus.

Wenn `p_base_revision` nicht zur aktuellen Revision passt, gibt `apply_vault_mutation()` kein erfolgreiches Write frei, sondern meldet `applied:false` mit `conflict_reason:'stale_base_revision'`. Die lokale Mutation bleibt dann in der Queue.

## Offline-Unlock-Flow

```text
1. isAppOnline() prüfen
2. Offline -> getOfflineCredentials() -> salt/verifier/kdfVersion setzen -> Unlock-Screen
3. Online  -> Profil laden -> Credentials + kdfVersion cachen
4. Netzwerkfehler -> Cache versuchen -> kein Cache -> Setup-Screen
```

`kdfVersion` wird mitgecacht, damit offline dieselbe KDF-Variante wie online verwendet wird. Der Cache enthält kein Master-Passwort im Klartext.

## Zentrale Funktionen

### `fetchRemoteOfflineSnapshot(userId)`

Lädt Items und Kategorien vom Server, fragt die aktuelle `remoteRevision` ab und speichert den Snapshot nur, wenn dadurch keine bekannte lokale High-Water-Mark unterschritten wird.

Falls die Datenbankmigration noch nicht ausgerollt ist, toleriert der Client eine fehlende `get_vault_sync_head`-RPC und speichert `remoteRevision:null`. Das ist ein Migrationspfad, keine Zielarchitektur.

### `enqueueOfflineMutation(mutation)`

Reiht lokale Änderungen ein und versieht sie mit der aktuellen `baseRemoteRevision`. Dadurch wird beim späteren Sync nachvollziehbar, auf welchem Remote-Stand die lokale Änderung basiert.

### `syncOfflineMutations(userId)`

Synchronisiert Queue-Einträge über `apply_vault_mutation()`. Nur erfolgreiche Mutationen werden aus der Queue entfernt. Bei Offline-/Netzwerkfehlern bricht der Sync ab; bei Revisionskonflikten bleibt die Mutation erhalten und kann später bewusst aufgelöst werden.

## Grenzen und offene Risiken

- Die Revision schützt bekannte Geräte gegen erkannte Rollbacks unter die zuletzt akzeptierte Revision. Sie ersetzt keinen extern auditierbaren Transparency Log.
- Ein bösartiger Server kann einem neuen Gerät einen alten, aber konsistenten Stand liefern, solange das Gerät keine vorherige High-Water-Mark besitzt.
- Browser-Speicher kann gelöscht werden. Dadurch geht die lokale High-Water-Mark verloren.
- Konfliktauflösung ist derzeit konservativ: stale Mutations bleiben queued, statt automatisch fremde Änderungen zu überschreiben.
