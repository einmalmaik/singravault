# Shared Collections Encryption Architecture

## Übersicht

Dieses Dokument beschreibt die Verschlüsselungs-Architektur für geteilte Sammlungen in Singra Vault. Die Implementierung verwendet einen Hybrid-Ansatz aus asymmetrischer (RSA-4096) und symmetrischer (AES-256-GCM) Verschlüsselung, um Zero-Knowledge-Architektur zu wahren.

## Verschlüsselungs-Architektur

### 1. User Key Pairs (RSA-4096)

Jeder Benutzer erhält ein Public/Private Key Pair:

**Tabelle: `public.user_keys`**
```sql
CREATE TABLE public.user_keys (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,                    -- JWK format, unverschlüsselt
    encrypted_private_key TEXT NOT NULL,         -- Mit Master-Passwort verschlüsselt
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);
```

**Eigenschaften:**
- Private Key wird mit dem Master-Passwort des Benutzers verschlüsselt (AES-256-GCM)
- Public Key wird unverschlüsselt gespeichert
- Private Key verlässt nie den Client in unverschlüsselter Form
- Key Pair wird bei der ersten Nutzung von Shared Collections generiert

### 2. Collection Shared Keys (AES-256)

Jede Collection hat einen zufälligen Shared Encryption Key:

**Tabelle: `public.collection_keys`**
```sql
CREATE TABLE public.collection_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID REFERENCES public.shared_collections(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    wrapped_key TEXT NOT NULL,                   -- Mit User Public Key verschlüsselt
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    UNIQUE (collection_id, user_id)
);
```

**Eigenschaften:**
- Shared Key wird für jedes Mitglied separat mit dessen Public Key verschlüsselt (Key Wrapping)
- Items werden mit dem Shared Key verschlüsselt
- Nur autorisierte Mitglieder können den Shared Key entschlüsseln

### 3. Encrypted Collection Items

Items in Collections werden mit dem Shared Key verschlüsselt:

**Tabelle: `public.shared_collection_items`**
```sql
ALTER TABLE public.shared_collection_items 
ADD COLUMN encrypted_data TEXT;  -- Mit Collection Shared Key verschlüsselt
```

## Key Wrapping Flow

### Collection erstellen

```
1. Benutzer erstellt neue Collection
2. System generiert zufälligen AES-256 Shared Key
3. System lädt Owner's Public Key
4. System verschlüsselt Shared Key mit Public Key (RSA-OAEP)
5. System speichert wrapped Key in collection_keys
```

### Mitglied hinzufügen

```
1. Owner fügt Mitglied zur Collection hinzu
2. System lädt Shared Key (entschlüsselt mit Owner's Private Key)
3. System lädt Member's Public Key
4. System verschlüsselt Shared Key mit Member's Public Key
5. System speichert wrapped Key in collection_keys
6. System fügt Mitglied zu shared_collection_members hinzu
```

### Item hinzufügen

```
1. Benutzer fügt Vault-Item zur Collection hinzu
2. System lädt wrapped Shared Key für aktuellen Benutzer
3. System entschlüsselt Shared Key mit Private Key
4. System verschlüsselt Item-Daten mit Shared Key (AES-256-GCM)
5. System speichert encrypted_data in shared_collection_items
```

### Item abrufen

```
1. Benutzer öffnet Collection
2. System lädt wrapped Shared Key für aktuellen Benutzer
3. System entschlüsselt Shared Key mit Private Key
4. System lädt alle Items der Collection
5. System entschlüsselt jedes Item mit Shared Key
6. System zeigt entschlüsselte Items an
```

## Sicherheits-Eigenschaften

### Zero-Knowledge-Architektur

✅ **Master-Passwort verlässt nie den Client**
- Wird nur client-seitig zur Entschlüsselung des Private Keys verwendet

✅ **Private Keys sind immer verschlüsselt**
- Verschlüsselung mit Master-Passwort (AES-256-GCM)
- Nur der Benutzer kann seinen Private Key entschlüsseln

✅ **Server sieht nur verschlüsselte Daten**
- Shared Keys sind mit Public Keys verschlüsselt
- Item-Daten sind mit Shared Keys verschlüsselt
- Server kann keine Daten entschlüsseln

✅ **Shared Keys nur für autorisierte Mitglieder**
- RLS-Policies stellen sicher, dass nur Mitglieder auf wrapped Keys zugreifen können
- Entfernte Mitglieder verlieren sofort Zugriff

### Key Rotation

**Wann ist Key Rotation notwendig?**
- Nach Entfernen eines Mitglieds (empfohlen, aber optional)
- Bei Verdacht auf kompromittierten Key
- Regelmäßig als Best Practice

**Key Rotation Prozess:**
```
1. Generiere neuen Shared Key
2. Lade alle Items der Collection
3. Entschlüssele Items mit altem Key
4. Verschlüssele Items mit neuem Key
5. Wrap neuen Key für alle verbleibenden Mitglieder
6. Aktualisiere collection_keys
7. Lösche alte wrapped Keys
```

**Wichtig:** Key Rotation ist eine atomare Transaktion. Bei Fehler wird alles zurückgerollt.

## RLS-Policies

### user_keys

```sql
-- Benutzer kann nur eigene Keys lesen/schreiben
CREATE POLICY "Users can read own keys"
    ON public.user_keys FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own keys"
    ON public.user_keys FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own keys"
    ON public.user_keys FOR UPDATE
    USING (auth.uid() = user_id);
```

### collection_keys

```sql
-- Benutzer kann Keys für eigene Collections lesen
CREATE POLICY "Users can read collection keys"
    ON public.collection_keys FOR SELECT
    USING (
        user_id = auth.uid() OR
        EXISTS (
            SELECT 1 FROM public.shared_collections
            WHERE id = collection_id AND owner_id = auth.uid()
        )
    );

-- Nur Collection-Besitzer können Keys hinzufügen/löschen
CREATE POLICY "Collection owners can insert keys"
    ON public.collection_keys FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM public.shared_collections
            WHERE id = collection_id AND owner_id = auth.uid()
        )
    );
```

## Audit Logging

### Tabelle: `public.collection_audit_log`

```sql
CREATE TABLE public.collection_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id UUID REFERENCES public.shared_collections(id) ON DELETE CASCADE NOT NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL
);
```

**Geloggte Aktionen:**
- `shared_collection_members_added` - Mitglied hinzugefügt
- `shared_collection_members_removed` - Mitglied entfernt
- `shared_collection_members_updated` - Permission geändert
- `shared_collection_items_added` - Item hinzugefügt
- `shared_collection_items_removed` - Item entfernt
- `shared_collection_items_updated` - Item bearbeitet

**Trigger:**
```sql
CREATE TRIGGER log_collection_members_changes
    AFTER INSERT OR UPDATE OR DELETE ON public.shared_collection_members
    FOR EACH ROW EXECUTE FUNCTION public.log_collection_change();

CREATE TRIGGER log_collection_items_changes
    AFTER INSERT OR UPDATE OR DELETE ON public.shared_collection_items
    FOR EACH ROW EXECUTE FUNCTION public.log_collection_change();
```

## Performance-Optimierungen

### Indizes

```sql
-- Schneller Zugriff auf Collection Keys
CREATE INDEX idx_collection_keys_collection ON public.collection_keys(collection_id);
CREATE INDEX idx_collection_keys_user ON public.collection_keys(user_id);

-- Schneller Zugriff auf Audit Log
CREATE INDEX idx_audit_log_collection ON public.collection_audit_log(collection_id, created_at DESC);
```

### Metadaten-Caching

```sql
-- Cached Counts für schnellere Anzeige
ALTER TABLE public.shared_collections
ADD COLUMN member_count INTEGER DEFAULT 0,
ADD COLUMN item_count INTEGER DEFAULT 0;

-- Automatische Updates via Trigger
CREATE TRIGGER update_member_count
    AFTER INSERT OR DELETE ON public.shared_collection_members
    FOR EACH ROW EXECUTE FUNCTION public.update_collection_member_count();

CREATE TRIGGER update_item_count
    AFTER INSERT OR DELETE ON public.shared_collection_items
    FOR EACH ROW EXECUTE FUNCTION public.update_collection_item_count();
```

## Migration Status

**Migration:** `20260211100000_family_collections_complete.sql`

**Status:** ✅ Angewendet

**Enthält:**
- ✅ Neue Tabellen (user_keys, collection_keys, collection_audit_log)
- ✅ Schema-Änderungen (encrypted_data, member_count, item_count)
- ✅ RLS-Policies für alle neuen Tabellen
- ✅ Trigger für Audit-Logging
- ✅ Trigger für Count-Updates
- ✅ Helper-Funktionen (check_family_size, check_subscription_tier)
- ✅ Daten-Migration für bestehende Collections

## Nächste Schritte

### Phase 1: Crypto Service (Priorität: HOCH)
- [ ] `generateUserKeyPair()` implementieren
- [ ] `generateSharedKey()` implementieren
- [ ] `wrapKey()` und `unwrapKey()` implementieren
- [ ] `encryptWithSharedKey()` und `decryptWithSharedKey()` implementieren

### Phase 2: Collection Service (Priorität: HOCH)
- [ ] `createCollectionWithKey()` implementieren
- [ ] `addMemberToCollection()` implementieren
- [ ] `addItemToCollection()` implementieren
- [ ] `getCollectionItems()` implementieren

### Phase 3: UI Components (Priorität: MITTEL)
- [ ] Key Pair Generation beim ersten Login
- [ ] Collection Details Page
- [ ] Add Member Dialog
- [ ] Add Item Dialog

### Phase 4: Testing (Priorität: HOCH)
- [ ] Unit Tests für Crypto Functions
- [ ] Integration Tests für Collection Flow
- [ ] Security Tests für Access Control
- [ ] Performance Tests für große Collections

## Referenzen

- [Web Crypto API - RSA-OAEP](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- [RFC 3394 - Key Wrapping](https://www.rfc-editor.org/rfc/rfc3394)
- [NIST SP 800-38F - Key Wrapping](https://csrc.nist.gov/publications/detail/sp/800-38f/final)
- Migration: `supabase/migrations/20260211100000_family_collections_complete.sql`
