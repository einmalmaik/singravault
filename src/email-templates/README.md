# E-Mail Templates

Diese Templates werden für Supabase Auth E-Mails verwendet und sind mit dem Singra Vault Branding gestaltet.

## Verfügbare Templates

| Template | Verwendung | Supabase Variable |
|----------|------------|-------------------|
| `confirm-email.html` | E-Mail-Bestätigung nach Registrierung | `{{ .Token }}` |
| `reset-password.html` | Passwort zurücksetzen | `{{ .Token }}` |
| `base.html` | Basis-Template für eigene Erweiterungen | `{{content}}` |

## Design-Elemente

- **Header:** Gradient von `#0a1628` zu `#0f1f38` (Dark Cosmic)
- **Akzentfarbe:** `#7ec8d9` (Singra Cyan)
- **Logo:** Gehostetes PNG (`singra-icon.png`) + "Singra Vault" Text
- **Code-Box:** Dunkler Hintergrund (`#0f1f38`) mit Cyan-Text
- **Dark Mode:** Automatische Anpassung via `prefers-color-scheme`
- **Responsive:** Funktioniert auf Desktop und Mobile

## Verwendung in Supabase

1. Gehe zu **Supabase Dashboard → Authentication → Email Templates**
2. Wähle den Template-Typ (Confirm signup, Reset password, etc.)
3. Kopiere den HTML-Inhalt des entsprechenden Templates
4. Füge ihn im "Message body" Feld ein
5. Speichere die Änderungen

## Anpassung

### Neues Template erstellen

1. Kopiere `base.html` als Ausgangspunkt
2. Ersetze `{{content}}` mit deinem Inhalt
3. Verwende Supabase-Variablen:
   - `{{ .Token }}` - OTP-Code
   - `{{ .ConfirmationURL }}` - Bestätigungs-Link
   - `{{ .Email }}` - E-Mail-Adresse

### Farbschema

```css
/* Header Gradient */
background: linear-gradient(135deg, #0a1628 0%, #0f1f38 100%);

/* Akzentfarbe (Buttons, Code, Links) */
color: #7ec8d9;

/* Text Colors */
color: #1a2332;  /* Dark text */
color: #4a5568;  /* Muted text */
color: #718096;  /* Light text */

/* Dark Mode */
background: #0a1628;  /* Dark bg */
color: #e2e8f0;       /* Light text */
```

## SMTP-Konfiguration

Die Templates werden über Resend SMTP gesendet:
- **Host:** `smtp.resend.com`
- **Port:** `465`
- **Username:** `resend`
- **Sender:** `noreply@mauntingstudios.de`
