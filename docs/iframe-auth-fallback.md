# Iframe Auth Fallback (2026-02-25)

## Problem

Login, Registrierung und Passwort-Reset funktionieren nicht in der Lovable-Preview (Iframe),
weil moderne Browser Third-Party Cookies blockieren. Das BFF-Pattern (`HttpOnly`, `SameSite=None`)
setzt Cookies von `supabase.co` auf einer `lovable.app`-Domain — das wird als Third-Party-Cookie
erkannt und blockiert.

## Lösung

### Frontend (`AuthContext.tsx`, `Auth.tsx`)

- **Iframe-Erkennung** via `window.self !== window.top`
- Im Iframe:
  - Session-Hydration über BFF-Cookie wird übersprungen
  - Login-Requests senden `skipCookie: true` im Body
  - `credentials: 'omit'` statt `'include'` (kein Cookie-Transport)
  - Session wird nur im Memory (Supabase JS Client) gehalten
- Standalone (eigener Tab):
  - Verhalten bleibt unverändert (BFF Cookie Pattern)

### Backend (`auth-session/index.ts`)

- Neuer Body-Parameter `skipCookie: boolean`
- Wenn `skipCookie === true`: kein `Set-Cookie` Header, Session wird nur als JSON zurückgegeben
- Das Frontend nutzt `supabase.auth.setSession()` um die Session im Memory zu halten

## Sicherheitsbetrachtung

- Im Iframe-Modus wird die Session nur im Memory gehalten (kein Cookie, kein localStorage)
- Bei Page-Reload geht die Session verloren (akzeptables Verhalten für Dev-Preview)
- In Produktion (eigener Tab/Domain) wird weiterhin das sichere BFF Cookie Pattern genutzt
- `skipCookie` hat keinen Einfluss auf die Authentifizierung selbst (Argon2id + 2FA bleiben identisch)

## Betroffene Dateien

- `src/contexts/AuthContext.tsx` — Iframe-Erkennung, Cookie-Hydration skip
- `src/pages/Auth.tsx` — `skipCookie` Flag, `credentials: 'omit'` im Iframe
- `supabase/functions/auth-session/index.ts` — `skipCookie` Parameter
