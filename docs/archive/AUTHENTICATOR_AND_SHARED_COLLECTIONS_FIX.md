# Authenticator & Shared Collections Fix

## Übersicht

Dieses Dokument beschreibt die Änderungen zur Behebung von zwei kritischen Problemen:

1. **Shared Collections 500 Error**: Datenbankfehler beim Laden von geteilten Sammlungen
2. **Integrierter Authenticator**: Fehlende Funktionalität zum Hinzufügen von TOTP-Items

## Änderungen

### 1. Shared Collections RLS-Policy Fix

**Problem:** Die RLS-Policy für `shared_collections` hatte eine potenzielle Rekursion, die zu 500-Fehlern führte.

**Lösung:** Migration `20260211000000_fix_shared_collections_rls.sql` angewendet, die die Policy vereinfacht:

```sql
-- Alt (mit potentieller Rekursion):
USING (
    auth.uid() = owner_id OR
    EXISTS (
        SELECT 1 FROM public.shared_collection_members scm
        WHERE scm.collection_id = shared_collections.id
        AND scm.user_id = auth.uid()
    )
)

-- Neu (ohne Rekursion):
USING (
    owner_id = auth.uid() OR
    id IN (
        SELECT collection_id 
        FROM public.shared_collection_members 
        WHERE user_id = auth.uid()
    )
)
```

**Vorteile:**
- Verwendet `IN` Subquery statt `EXISTS` mit Korrelation
- Vermeidet potenzielle Rekursion durch Entfernung der korrelierten Unterabfrage
- Bessere Performance durch einfachere Query-Struktur
- Policy enthält jetzt Dokumentations-Kommentar für zukünftige Wartung

**Status:** ✅ Migration angewendet und getestet

### 2. TOTP-Utilities

**Neue Funktionen in `src/services/totpService.ts`:**

#### `validateTOTPSecret(secret: string)`

Validiert TOTP-Secrets mit detaillierten Fehlermeldungen:

```typescript
export function validateTOTPSecret(secret: string): { valid: boolean; error?: string } {
    const cleaned = secret.replace(/\s/g, '').toUpperCase();
    
    if (cleaned.length < 16) {
        return { valid: false, error: 'Secret zu kurz (mindestens 16 Zeichen)' };
    }
    
    if (!/^[A-Z2-7]+=*$/.test(cleaned)) {
        return { valid: false, error: 'Ungültiges Format (nur A-Z und 2-7 erlaubt)' };
    }
    
    return { valid: true };
}
```

**Features:**
- Entfernt automatisch Leerzeichen
- Prüft Base32-Format (A-Z, 2-7)
- Prüft Mindestlänge (16 Zeichen)
- Gibt spezifische Fehlermeldungen zurück

#### `parseOTPAuthUri(uri: string)`

Parst `otpauth://totp/...` URIs aus QR-Codes:

```typescript
export function parseOTPAuthUri(uri: string): {
    secret: string;
    issuer?: string;
    label?: string;
} | null {
    try {
        const url = new URL(uri);
        
        if (url.protocol !== 'otpauth:' || url.host !== 'totp') {
            return null;
        }
        
        const secret = url.searchParams.get('secret');
        if (!secret) return null;
        
        const issuer = url.searchParams.get('issuer') || undefined;
        const label = decodeURIComponent(url.pathname.slice(1)) || undefined;
        
        return { secret: secret.toUpperCase(), issuer, label };
    } catch {
        return null;
    }
}
```

**Features:**
- Extrahiert TOTP-Secret aus URI
- Extrahiert Issuer (z.B. "Google")
- Extrahiert Label (z.B. "user@example.com")
- Gibt `null` zurück bei ungültigen URIs

### 3. AuthenticatorPage Fix

**Problem:** Der "Erstes 2FA-Konto einrichten" Button leitete fälschlicherweise zu `/settings` weiter.

**Lösung:** Button öffnet jetzt den Dialog zum Erstellen eines TOTP-Items:

```typescript
// Alt:
<Button variant="outline" onClick={() => navigate('/settings')}>
    {t('authenticator.setupFirst')}
</Button>

// Neu:
<Button variant="outline" onClick={() => setDialogOpen(true)}>
    <Plus className="w-4 h-4 mr-2" />
    {t('authenticator.addFirst')}
</Button>
```

**Vorteile:**
- Benutzer können direkt TOTP-Items erstellen
- Kein Umweg über Einstellungen nötig
- Konsistentes UX-Verhalten

### 4. Internationalisierung

**Neue Übersetzungskeys:**

**Deutsch (`src/i18n/locales/de.json`):**
```json
{
  "authenticator": {
    "addFirst": "Erstes TOTP-Konto hinzufügen",
    "manualEntry": "Manuell eingeben",
    "secretLabel": "TOTP-Secret",
    "secretPlaceholder": "JBSW Y3DP EHPK 3PXP",
    "invalidSecret": "Ungültiges TOTP-Secret",
    "secretTooShort": "Secret zu kurz (mindestens 16 Zeichen)"
  }
}
```

**Englisch (`src/i18n/locales/en.json`):**
```json
{
  "authenticator": {
    "addFirst": "Add first TOTP account",
    "manualEntry": "Manual entry",
    "secretLabel": "TOTP Secret",
    "secretPlaceholder": "JBSW Y3DP EHPK 3PXP",
    "invalidSecret": "Invalid TOTP secret",
    "secretTooShort": "Secret too short (minimum 16 characters)"
  }
}
```

## Verwendung

### Integrierter Authenticator

Der integrierte Authenticator ist eine **Premium-Funktion**, die es Benutzern ermöglicht, TOTP-Codes für externe Services (Google, GitHub, Dropbox, etc.) direkt in ihrem Passwort-Tresor zu speichern.

**Unterschied zur Account-2FA:**
- **Account-2FA** (`/settings` → Sicherheit): Schützt den Singra Vault Account selbst
- **Integrierter Authenticator** (`/authenticator`): Generiert Codes für ANDERE Services

**Workflow:**
1. Benutzer navigiert zu `/authenticator`
2. Klickt auf "Hinzufügen" oder "Erstes TOTP-Konto hinzufügen"
3. Dialog öffnet sich mit Typ "TOTP"
4. Benutzer gibt TOTP-Secret ein (manuell oder via QR-Code)
5. Secret wird validiert mit `validateTOTPSecret()`
6. Item wird im Tresor gespeichert
7. TOTP-Codes werden automatisch generiert und alle 30 Sekunden aktualisiert

### Shared Collections

Nach Anwendung der Migration sollten geteilte Sammlungen ohne 500-Fehler laden.

**Testen:**
```bash
# Migration anwenden
supabase db reset

# Oder nur die neue Migration
supabase migration up
```

## Sicherheitsüberlegungen

### TOTP-Secret-Speicherung

- TOTP-Secrets werden wie Passwörter verschlüsselt gespeichert
- Verschlüsselung erfolgt client-seitig mit AES-256-GCM
- Master-Passwort wird nie an den Server gesendet
- Secrets werden nur im Speicher entschlüsselt

### RLS-Policy-Änderungen

- Die neue Policy ist sicherer, da sie keine Rekursion zulässt
- Benutzer können nur eigene oder explizit geteilte Sammlungen sehen
- Keine Änderung an den Berechtigungen, nur an der Implementierung

## Testing

### Manuelle Tests

1. **Shared Collections:**
   - Navigiere zu `/settings` → Geteilte Sammlungen
   - Erstelle eine neue Sammlung
   - Verifiziere, dass keine 500-Fehler auftreten

2. **Authenticator:**
   - Navigiere zu `/authenticator`
   - Klicke auf "Erstes TOTP-Konto hinzufügen"
   - Gib ein gültiges TOTP-Secret ein (z.B. `JBSWY3DPEHPK3PXP`)
   - Verifiziere, dass ein 6-stelliger Code generiert wird
   - Warte 30 Sekunden und verifiziere, dass der Code sich ändert

### Automatisierte Tests

Unit-Tests für TOTP-Utilities können mit Vitest geschrieben werden:

```typescript
import { describe, it, expect } from 'vitest';
import { validateTOTPSecret, parseOTPAuthUri } from '@/services/totpService';

describe('validateTOTPSecret', () => {
    it('should accept valid Base32 secrets', () => {
        const result = validateTOTPSecret('JBSWY3DPEHPK3PXP');
        expect(result.valid).toBe(true);
    });

    it('should reject secrets that are too short', () => {
        const result = validateTOTPSecret('JBSWY3DP');
        expect(result.valid).toBe(false);
        expect(result.error).toContain('zu kurz');
    });

    it('should reject invalid characters', () => {
        const result = validateTOTPSecret('INVALID-SECRET-123');
        expect(result.valid).toBe(false);
        expect(result.error).toContain('Ungültiges Format');
    });
});

describe('parseOTPAuthUri', () => {
    it('should parse valid otpauth URIs', () => {
        const uri = 'otpauth://totp/Google:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Google';
        const result = parseOTPAuthUri(uri);
        
        expect(result).not.toBeNull();
        expect(result?.secret).toBe('JBSWY3DPEHPK3PXP');
        expect(result?.issuer).toBe('Google');
        expect(result?.label).toBe('Google:user@example.com');
    });

    it('should return null for invalid URIs', () => {
        const result = parseOTPAuthUri('https://example.com');
        expect(result).toBeNull();
    });
});
```

## Migration

### Datenbank-Migration anwenden

**Status:** ✅ Migration `20260211000000_fix_shared_collections_rls.sql` wurde bereits angewendet.

Die Migration enthält:
- DROP der alten RLS-Policy
- CREATE der neuen vereinfachten Policy
- COMMENT zur Dokumentation der Policy-Logik

```bash
# Lokale Entwicklung (falls noch nicht angewendet)
supabase db reset

# Oder nur die neue Migration
supabase migration up

# Production (über Supabase Dashboard)
# 1. Navigiere zu Database → Migrations
# 2. Lade die neue Migration hoch
# 3. Führe sie aus
```

### Rollback (falls nötig)

Falls die neue RLS-Policy Probleme verursacht, kann die alte Policy wiederhergestellt werden:

```sql
-- Alte Policy wiederherstellen
DROP POLICY IF EXISTS "Users can view own or shared collections" ON public.shared_collections;

CREATE POLICY "Users can view own or shared collections"
    ON public.shared_collections FOR SELECT
    TO authenticated
    USING (
        auth.uid() = owner_id OR
        EXISTS (
            SELECT 1 FROM public.shared_collection_members scm
            WHERE scm.collection_id = shared_collections.id
            AND scm.user_id = auth.uid()
        )
    );
```

## Bekannte Einschränkungen

1. **QR-Code-Scanning:** Aktuell nicht implementiert. Benutzer müssen TOTP-Secrets manuell eingeben.
2. **TOTP-Secret-Validierung:** Erfolgt nur client-seitig. Server-seitige Validierung könnte hinzugefügt werden.
3. **Shared Collections Performance:** Bei sehr vielen Sammlungen könnte die Performance leiden. Monitoring empfohlen.

## Zukünftige Verbesserungen

1. **QR-Code-Scanner:** Integration einer QR-Code-Scanner-Bibliothek (z.B. `html5-qrcode`)
2. **TOTP-Import:** Bulk-Import von TOTP-Secrets aus anderen Authenticator-Apps
3. **TOTP-Export:** Export von TOTP-Secrets für Backup-Zwecke
4. **Shared Collections Pagination:** Pagination für große Listen von Sammlungen

## Referenzen

- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4648 - Base32 Encoding](https://datatracker.ietf.org/doc/html/rfc4648)
- [OTPAuth URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [PostgreSQL RLS Documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
