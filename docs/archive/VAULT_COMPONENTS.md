# Vault-Komponenten — Vault-UI

> **Dateien:**  
> `src/pages/VaultPage.tsx`  
> `src/components/vault/VaultSidebar.tsx`  
> `src/components/vault/VaultItemList.tsx`  
> `src/components/vault/VaultItemDialog.tsx`  
> `src/components/vault/PasswordGenerator.tsx`  
> `src/components/vault/TotpDisplay.tsx`  
> `src/components/vault/CategoryDialog.tsx`  
> `src/components/vault/CategoryIcon.tsx`

---

## VaultPage

> **Datei:** `src/pages/VaultPage.tsx`

Die Hauptseite des Vaults. Koordiniert alle Vault-Komponenten.

### State
| State | Typ | Zweck |
|---|---|---|
| `searchQuery` | `string` | Suchbegriff für Item-Filter |
| `filter` | `ItemFilter` | Aktiver Quick-Filter (`all`, `favorite`, `recent`, `weak`) |
| `selectedCategory` | `string \| null` | Ausgewählte Kategorie |
| `viewMode` | `ViewMode` | Ansichtsmodus (`grid`, `list`) |
| `dialogOpen` | `boolean` | Item-Dialog geöffnet? |
| `editingItemId` | `string \| null` | Zu bearbeitendes Item |
| `refreshKey` | `number` | Increment-Counter um Item-Liste neu zu laden |

### Initialisierung / Offline-Sync (useEffect)

**Ablauf:**
1. Wartet bis User geladen und Vault entsperrt
2. Prüft Netzwerk-Status via `isAppOnline()`
3. **Online:** Ruft `syncOfflineMutations(userId)` auf
4. Bei `processed > 0` → zeigt Success-Toast an
5. Lädt danach Remote-Snapshot via `fetchRemoteOfflineSnapshot()`

### Conditional Rendering

```
isLoading?                → Loading-Spinner
!hasMasterPassword?       → <MasterPasswordSetup />
isLocked?                 → <VaultUnlock />
Sonst                     → <VaultSidebar /> + <VaultItemList />
```

### `handleNewItem()`
Öffnet den Dialog für ein neues Item: `editingItemId: null`, `dialogOpen: true`

### `handleEditItem(itemId)`
Öffnet den Dialog im Bearbeitungsmodus: `editingItemId: itemId`, `dialogOpen: true`

### `handleSave()`
Schließt den Dialog und inkrementiert `refreshKey` um die Liste zu aktualisieren.

---

## VaultSidebar

> **Datei:** `src/components/vault/VaultSidebar.tsx`

Die Navigation im Vault mit Kategorien, Quick-Filtern und Statistiken.

### Props
| Prop | Typ | Beschreibung |
|---|---|---|
| `selectedCategory` | `string \| null` | Aktive Kategorie |
| `onSelectCategory` | `(id) => void` | Callback bei Kategorie-Wechsel |
| `compactMode` | `boolean` | Kompakte Ansicht (nur Icons) |
| `onActionComplete` | `() => void` | Callback nach Kategorie-Änderung |

### Daten laden (useEffect)

**Ablauf:**
1. Prüft Netzwerk-Status via `isAppOnline()`
2. **Online:** Fragt Supabase nach Vault-ID, Categories (mit Item-Count), allen Items
3. **Offline:** Lädt aus `loadVaultSnapshot()` und berechnet Counts lokal
4. **Entschlüsselung:** Entschlüsselt Kategorienamen (`enc:cat:v1:` Prefix → `decryptData()`)
5. Baut Statistiken: Gesamt, Favoriten, Schwach, Kürzlich

### Kategorien-Verwaltung

#### `handleAddCategory()`
Öffnet CategoryDialog im Erstellen-Modus.

#### `handleEditCategory(category)`
Öffnet CategoryDialog im Bearbeiten-Modus.

#### `handleCategoryChange()`
Callback nach Kategorie-Erstellung/-Bearbeitung → lädt Daten neu.

### SidebarItem (Sub-Komponente)

Einzelnes Navigations-Element mit Icon, Label, Count und Active-State.

---

## VaultItemList

> **Datei:** `src/components/vault/VaultItemList.tsx`

Zeigt die Vault-Einträge in Grid- oder Listenansicht an.

### Props
| Prop | Typ | Beschreibung |
|---|---|---|
| `searchQuery` | `string` | Suchbegriff |
| `filter` | `ItemFilter` | Quick-Filter |
| `categoryId` | `string \| null` | Kategorie-Filter |
| `viewMode` | `ViewMode` | `'grid'` oder `'list'` |
| `onEditItem` | `(id) => void` | Klick auf Item |
| `refreshKey` | `number` | Trigger für Neuladen |

### `fetchItems()` (useEffect)

**Ablauf:**
1. Prüft Online-Status
2. **Online:** Fragt Supabase `vault_items` mit optionalem `category_id`-Filter
3. **Offline:** Lädt aus Snapshot und filtert lokal
4. **Entschlüsselung:** Versucht jedes Item zu entschlüsseln via `decryptVaultItem()`
   - Fehler → Item erhält Placeholder-Titel `'Encrypted Item'`
   - Offline → aktualisiert den lokalen Snapshot mit entschlüsseltem Titel
5. **Filterung:**
   - `favorite` → nur `is_favorite: true`
   - `recent` → sortiert nach `updated_at`, letzte 10
   - `weak` → Passwort-Stärke < 3
   - Suche → durchsucht `title`, `username`, `website_url`

---

## VaultItemDialog

> **Datei:** `src/components/vault/VaultItemDialog.tsx`

Modal zum Erstellen und Bearbeiten von Vault-Einträgen.

### Props
| Prop | Typ | Beschreibung |
|---|---|---|
| `open` | `boolean` | Dialog geöffnet? |
| `onOpenChange` | `(open) => void` | Callback für Dialog-Status |
| `itemId` | `string \| null` | `null` = Neues Item |
| `onSave` | `() => void` | Callback nach Speichern |

### Formular-Schema (Zod)

```typescript
z.object({
    title: z.string().min(1, 'Title is required'),
    url: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    notes: z.string().optional(),
    totpSecret: z.string().optional(),
    isFavorite: z.boolean().default(false),
})
```

### `normalizeUrl(url): string | null` (Hilfsfunktion)
Prefix-Logik: Wenn URL keinen `://` enthält → `https://` wird vorangestellt.

### `loadItem()` (useEffect)

Laden eines existierenden Items zum Bearbeiten.

**Ablauf:**
1. Kein `itemId` → leert das Formular
2. **Online:** Lädt Item und Kategorie von Supabase
3. **Offline:** Lädt aus Snapshot
4. Entschlüsselt `encrypted_data` via `decryptVaultItem()`
5. Entschlüsselt Kategorie-ID (wenn verschlüsselt mit `enc:cat:v1:` Prefix)
6. Befüllt das React-Hook-Form

### `onSubmit(data)` (Formular-Handler)

**Ablauf:**
1. Baut `VaultItemData` zusammen
2. Verschlüsselt via `encryptVaultItem()`
3. Verschlüsselt Kategorie-ID (→ `enc:cat:v1:` + `encryptData()`)
4. Normalisiert URL
5. **Online:**
   - Neues Item → `supabase.from('vault_items').insert()`
   - Bearbeiten → `supabase.from('vault_items').update()`
   - Aktualisiert lokalen Snapshot via `upsertOfflineItemRow()`
6. **Offline:**
   - Baut Item-Row via `buildVaultItemRowFromInsert()`
   - Aktualisiert lokalen Snapshot
   - Reiht Mutation in Queue via `enqueueOfflineMutation()`
7. Zeigt Success-Toast an
8. Ruft `onSave()` Callback auf

### `handleDelete()`

**Ablauf:**
1. **Online:** `supabase.from('vault_items').delete()`
2. **Offline:** Entfernt aus Snapshot + enqueued `delete_item` Mutation
3. Zeigt Toast an, schließt Dialog

### `handleGeneratedPassword(password)`
Setzt das Passwort-Feld im Formular auf den generierten Wert.

---

## PasswordGenerator

> **Datei:** `src/components/vault/PasswordGenerator.tsx`

UI-Komponente für Passwort- und Passphrasen-Generierung.

### Props
| Prop | Typ | Beschreibung |
|---|---|---|
| `onPasswordGenerated` | `(password) => void` | Callback mit generiertem Passwort |

### Features
- Toggle zwischen Passwort/Passphrase-Modus
- Konfigurierbarer Schieberegler für Länge (4–128) / Wortanzahl (3–10)
- Checkboxen für Zeichenklassen
- Live-Stärke-Anzeige (Progress-Bar mit Farbe)
- Copy-to-Clipboard Button
- Regenerieren-Button

### State
- `generatedPassword` — der aktuelle generierte Wert
- `mode` — `'password'` oder `'passphrase'`
- `passwordOptions` / `passphraseOptions` — Konfiguration
- `strength` — berechnete Stärke via `calculateStrength()`

---

## TotpDisplay

> **Datei:** `src/components/vault/TotpDisplay.tsx`

Zeigt den aktuellen TOTP-Code mit Countdown an.

### Props
| Prop | Typ | Beschreibung |
|---|---|---|
| `secret` | `string` | Base32 TOTP-Secret |

### State
- `code` — aktueller 6-stelliger Code
- `timeRemaining` — verbleibende Sekunden (0–30)

### Timer (useEffect)
1. Generiert TOTP-Code sofort via `generateTOTP(secret)`
2. Startet 1-Sekunden-Interval:
   - `getTimeRemaining()` → aktualisiert Countdown
   - Bei 30 → neuer Code generiert
3. Cleanup: Interval bei Unmount gelöscht

### Darstellung
- Formatierter Code: `123 456` (mit Leerzeichen)
- Kreisförmiger Countdown-Indikator (SVG `stroke-dasharray`)
- Farbe wechselt zu Rot unter 5 Sekunden
- Copy-to-Clipboard-Funktion (nur Code, ohne Leerzeichen)

---

## CategoryDialog

> **Datei:** `src/components/vault/CategoryDialog.tsx`

Erstellen und Bearbeiten von Kategorien mit Icon- und Farbauswahl.

### Features
- Erstellen/Bearbeiten mit Name, Icon, Farbe
- Löschen mit Bestätigung und Warnung über verwaiste Items
- Verschlüsselte Kategorienamen: `enc:cat:v1:` + verschlüsselter Name
- Offline-Support: Enqueued Mutations bei fehlender Verbindung

### `handleSave()`

**Ablauf:**
1. Verschlüsselt den Kategorienamen via `encryptData()` → `enc:cat:v1:` Prefix
2. **Edit:** `supabase.from('categories').update()` oder Offline-Queue
3. **Create:** `supabase.from('categories').insert()` oder Offline-Queue
4. Aktualisiert lokalen Snapshot

### `handleDelete()`

**Ablauf:**
1. `supabase.from('categories').delete()` oder Offline-Queue
2. Entfernt aus lokalem Snapshot
3. Zeigt Warnung: Items verlieren Kategoriezuordnung

---

## CategoryIcon

> **Datei:** `src/components/vault/CategoryIcon.tsx`

Rendert ein Lucide-Icon basierend auf dem Icon-Namen als String.

### `getCategoryIcon(iconName): Component`
Mapping von String-Name zu Lucide-Komponente. Unterstützt ca. 40 Icons (z.B. `'folder'`, `'star'`, `'lock'`, `'globe'`). Fallback: `FolderIcon`.
