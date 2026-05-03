# Family Collections Implementation

## Übersicht

Diese Dokumentation beschreibt die Implementierung der vollständigen Funktionalität für Familien-Organisation und geteilte Sammlungen in Singra Vault.

**Datum:** 2026-02-11  
**Status:** In Entwicklung  
**Spec:** `.kiro/specs/family-shared-collections-complete/`

## Implementierte Features

### Phase 1: Datenbank-Schema ✅

**Migration:** `supabase/migrations/20260211100000_family_collections_complete.sql`

#### Neue Tabellen

1. **user_keys**
   - Speichert RSA-4096 Public/Private Key Pairs für jeden Benutzer
   - Private Key ist mit Master-Passwort verschlüsselt (AES-256-GCM)
   - Public Key ist unverschlüsselt für Key Wrapping

2. **collection_keys**
   - Speichert Shared Encryption Keys für Collections
   - Jeder Key ist "wrapped" (verschlüsselt) mit dem Public Key des jeweiligen Mitglieds
   - UNIQUE constraint auf (collection_id, user_id)

3. **collection_audit_log**
   - Protokolliert alle Änderungen an Collections
   - Speichert action, user_id, details (JSONB)
   - Nur für Collection-Besitzer und Mitglieder lesbar

#### Schema-Änderungen

- `shared_collection_items.encrypted_data` - Verschlüsselte Item-Daten
- `shared_collections.member_count` - Anzahl der Mitglieder
- `shared_collections.item_count` - Anzahl der Items

#### RLS-Policies

- Benutzer können nur eigene `user_keys` lesen/schreiben
- Benutzer können `collection_keys` für eigene Collections lesen
- Collection-Besitzer können Keys für Mitglieder erstellen/löschen
- Audit-Log ist nur für Besitzer und Mitglieder lesbar

#### Trigger

- `log_collection_change()` - Automatisches Logging bei INSERT/UPDATE/DELETE
- `update_collection_member_count()` - Aktualisiert member_count
- `update_collection_item_count()` - Aktualisiert item_count

### Phase 2: Crypto Service ✅

**Datei:** `src/services/cryptoService.ts`

Alle Crypto-Funktionen waren bereits implementiert:

- `generateUserKeyPair()` - RSA-4096 Key Pair Generation
- `generateSharedKey()` - AES-256 Shared Key Generation
- `wrapKey()` - Verschlüsselt Shared Key mit Public Key (RSA-OAEP)
- `unwrapKey()` - Entschlüsselt Shared Key mit Private Key
- `encryptWithSharedKey()` - Verschlüsselt Item mit Shared Key (AES-256-GCM)
- `decryptWithSharedKey()` - Entschlüsselt Item mit Shared Key

### Phase 3: Collection Service ✅

**Datei:** `src/services/collectionService.ts`

Alle Collection-Funktionen waren bereits implementiert:

- `createCollectionWithKey()` - Erstellt Collection mit Shared Key
- `getAllCollections()` - Lädt eigene + geteilte Collections
- `addMemberToCollection()` - Fügt Mitglied hinzu (mit Key Wrapping)
- `removeMemberFromCollection()` - Entfernt Mitglied
- `getCollectionMembers()` - Lädt alle Mitglieder
- `updateMemberPermission()` - Ändert Permission (view/edit)
- `addItemToCollection()` - Fügt Item hinzu (verschlüsselt)
- `removeItemFromCollection()` - Entfernt Item
- `getCollectionItems()` - Lädt Items (entschlüsselt)
- `getCollectionAuditLog()` - Lädt Audit-Log
- `rotateCollectionKey()` - Rotiert Shared Key

### Phase 4: Family Service Erweiterungen ✅

**Datei:** `src/services/familyService.ts`

#### Neue Funktionen

- `getPendingInvitations()` - Lädt ausstehende Einladungen für aktuellen Benutzer
- `acceptFamilyInvitation()` - Nimmt Einladung an
- `declineFamilyInvitation()` - Lehnt Einladung ab

#### Edge Function: invite-family-member ✅

**Datei:** `supabase/functions/invite-family-member/index.ts`

**Neue Validierungen:**

1. **Subscription-Tier-Prüfung**
   - Prüft, ob Benutzer "families" Tier hat
   - Gibt 403 Fehler zurück, wenn nicht

2. **Familiengröße-Validierung**
   - Zählt aktive Familienmitglieder
   - Gibt 400 Fehler zurück, wenn >= 6 Mitglieder

#### Edge Function: accept-family-invitation ✅

**Datei:** `supabase/functions/accept-family-invitation/index.ts`

**Funktionalität:**

1. Validiert JWT Token
2. Prüft, ob Einladung existiert und für aktuellen Benutzer ist
3. Aktualisiert `member_user_id`, `status`, `joined_at`
4. Sendet Benachrichtigungs-E-Mail an Einlader

### Phase 5: UI-Komponenten ✅

#### PendingInvitationsAlert ✅

**Datei:** `src/components/settings/PendingInvitationsAlert.tsx`

**Funktionalität:**

- Zeigt Banner mit ausstehenden Einladungen
- Buttons zum Annehmen/Ablehnen
- Automatisches Neuladen nach Aktion
- Toast-Benachrichtigungen

**Integration:**

- Eingebunden in `FamilyOrganizationSettings.tsx`
- Wird nur angezeigt, wenn Einladungen vorhanden sind

### Phase 6: Internationalisierung ✅

**Dateien:**
- `src/i18n/locales/de.json`
- `src/i18n/locales/en.json`

**Neue Übersetzungs-Keys:**

```json
{
  "family": {
    "pendingInvitation": "...",
    "invitationMessage": "...",
    "accept": "...",
    "decline": "...",
    "invitationAccepted": "...",
    "invitationAcceptError": "...",
    "invitationDeclined": "...",
    "invitationDeclineError": "..."
  },
  "sharedCollections": {
    "myCollections": "...",
    "sharedWithMe": "...",
    "owner": "...",
    "member": "...",
    "viewPermission": "...",
    "editPermission": "...",
    "addMember": "...",
    "addItem": "...",
    "removeMember": "...",
    "removeItem": "...",
    "memberAdded": "...",
    "memberAddError": "...",
    "memberRemoved": "...",
    "memberRemoveError": "...",
    "itemAdded": "...",
    "itemAddError": "...",
    "itemRemoved": "...",
    "itemRemoveError": "...",
    "sharedBadge": "...",
    "rotateKey": "...",
    "rotateKeyWarning": "...",
    "rotateKeySuccess": "...",
    "rotateKeyError": "..."
  }
}
```

## Verschlüsselungs-Architektur

### Hybrid-Ansatz

**Asymmetrische Verschlüsselung (RSA-4096):**
- Jeder Benutzer hat ein Public/Private Key Pair
- Private Key ist mit Master-Passwort verschlüsselt
- Public Key ist unverschlüsselt in der Datenbank

**Symmetrische Verschlüsselung (AES-256-GCM):**
- Jede Collection hat einen Shared Encryption Key
- Items werden mit diesem Key verschlüsselt
- Shared Key wird für jedes Mitglied mit dessen Public Key "wrapped"

### Key Wrapping Flow

```
Collection erstellen:
1. Generiere zufälligen Shared Key (AES-256)
2. Verschlüssele Shared Key mit Owner's Public Key (RSA-OAEP)
3. Speichere wrapped Key in collection_keys

Mitglied hinzufügen:
1. Lade Shared Key (entschlüsselt mit Owner's Private Key)
2. Verschlüssele Shared Key mit Member's Public Key
3. Speichere wrapped Key in collection_keys

Item abrufen:
1. Lade wrapped Shared Key für aktuellen Benutzer
2. Entschlüssele Shared Key mit Private Key
3. Entschlüssele Item mit Shared Key
```

## Sicherheits-Überlegungen

### Zero-Knowledge Architektur

✅ Master-Passwort verlässt nie den Client  
✅ Private Keys sind immer verschlüsselt  
✅ Server sieht nur verschlüsselte Daten  
✅ Shared Keys sind nur für autorisierte Mitglieder zugänglich

### Key Rotation

- Empfohlen nach Entfernen eines Mitglieds
- Optional (Benutzer-Entscheidung)
- Kann zeitaufwändig sein bei vielen Items
- Alle Items werden mit neuem Key neu verschlüsselt
- Alte Keys werden ungültig

### Audit Logging

- Alle Änderungen werden protokolliert
- Logs sind nur für Collection-Besitzer sichtbar
- Logs enthalten keine sensiblen Daten
- Automatisch via Trigger

## Nächste Schritte

### Ausstehende Tasks

- [ ] Task 5.2: CollectionDetailsPage
- [ ] Task 5.3: AddMemberDialog
- [ ] Task 5.4: AddItemDialog
- [ ] Task 5.5: SharedItemBadge
- [ ] Task 5.6: Vault-Anzeige erweitern
- [ ] Task 5.7: SharedCollectionsSettings erweitern
- [ ] Task 7.2: add-collection-member Edge Function
- [ ] Task 7.3: remove-collection-member Edge Function
- [ ] Task 8.2: Key Rotation UI
- [ ] Task 9.1: Offline Vault Service erweitern
- [ ] Task 9.2: Conflict Resolution
- [ ] Task 10.1-10.3: Testing
- [ ] Task 11.1-11.3: Dokumentation
- [ ] Task 12.1-12.3: Migration & Deployment

## Testing

### Unit Tests

- [ ] Crypto Functions (generateUserKeyPair, wrapKey, unwrapKey)
- [ ] Collection Service Functions
- [ ] Family Service Functions

### Integration Tests

- [ ] End-to-End Collection Flow
- [ ] Key Rotation
- [ ] Einladungs-Flow

### Security Tests

- [ ] Access Control (Viewer kann nicht bearbeiten)
- [ ] Nicht-Mitglieder können nicht zugreifen
- [ ] Entfernte Mitglieder können nicht zugreifen
- [ ] Falsches Passwort schlägt fehl

## Deployment

### Voraussetzungen

1. Supabase CLI >= 2.67.1
2. Node.js >= 20.19.0
3. Aktive Supabase-Instanz

### Deployment-Schritte

```bash
# 1. Migrationen anwenden
supabase db push

# 2. Edge Functions deployen
supabase functions deploy accept-family-invitation
supabase functions deploy invite-family-member

# 3. Tests ausführen
npm run test

# 4. Build erstellen
npm run build

# 5. Deployment
# (je nach Hosting-Provider)
```

## Referenzen

- [Web Crypto API - RSA-OAEP](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- [Key Wrapping Best Practices](https://www.rfc-editor.org/rfc/rfc3394)
- [Zero-Knowledge Architecture](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Design Document](../.kiro/specs/family-shared-collections-complete/design.md)
- [Requirements Document](../.kiro/specs/family-shared-collections-complete/requirements.md)
