# Edge Function Manifest - Open Core Split

Dieses Manifest definiert, welche Edge Functions zum öffentlichen Core und
welche zum privaten Premium-Paket (`@singra/premium`) gehören.

## Core Functions (öffentlich)

Diese Functions bleiben im `singra-vault` Repository und sind die einzigen
Functions, die im Open-Core `supabase/config.toml` gelistet werden dürfen:

| Function | Zweck |
|----------|-------|
| `auth-opaque` | OPAQUE-Protokoll-Login und OPAQUE-2FA-Abschluss |
| `auth-register` | OPAQUE-only Benutzerregistrierung |
| `auth-recovery` | Account-Wiederherstellung |
| `auth-reset-password` | OPAQUE-only Passwort zurücksetzen |
| `auth-2fa` | Zentrale serverseitige 2FA-/VaultFA-Validierung |
| `auth-session` | Session-Hydration, Logout und OAuth-Sync; kein Passwort-Login |
| `webauthn` | Passkey/WebAuthn-Operationen |
| `rate-limit` | Rate-Limiting |
| `account-delete` | Authentifizierte und gedrosselte Account-Löschung |

Private Admin-, Support-, Billing-, Family- und Release-Functions werden nicht
aus diesem Repository deployt und dürfen nicht als `verify_jwt=false` Core-Stubs
in `supabase/config.toml` stehen bleiben.

## Premium Functions (privat -> `@singra/premium`)

Diese Functions gehören ins private Premium-Repository. Open-Core darf sie
nicht nachbauen und nicht mit echten Admin-/Support-Rechten deploybar machen.

### Stripe / Abo-System

| Function | Zweck |
|----------|-------|
| `create-checkout-session` | Stripe Checkout erstellen |
| `create-portal-session` | Stripe Customer Portal |
| `cancel-subscription` | Abo kündigen (§312k BGB) |
| `stripe-webhook` | Stripe Event-Verarbeitung |

### Family & Emergency Access

| Function | Zweck |
|----------|-------|
| `invite-family-member` | Familienmitglied einladen |
| `accept-family-invitation` | Einladung annehmen |
| `invite-emergency-access` | Notfallzugang einrichten |

### Admin / Support / Release

| Function | Zweck |
|----------|-------|
| `admin-team` | Team-Rollen & Permissions |
| `desktop-release` | Desktop-Downloads für Website/Landing bereitstellen |
| `support-submit` | Support-Ticket erstellen |
| `support-list` | Tickets auflisten / Details / Antworten |
| `support-metrics` | SLA-Metriken (Admin) |
| `admin-support` | Admin-Support-Panel Backend |
| `send-test-mail` | Test-E-Mail senden |

## Shared

| Datei | Gehört zu |
|-------|-----------|
| `_shared/cors.ts` | Core (wird von beiden genutzt) |
| `_shared/twoFactor.ts` | Core |
| `_shared/authRateLimit.ts` | Core |

## Repo-Split Anleitung

1. Premium Functions bleiben im privaten Premium-Repo.
2. Open-Core `supabase/config.toml` enthält nur Core Functions.
3. Premium-Repo bekommt eigenes `supabase/config.toml` mit Premium-Einträgen.
4. Shared Security-Utilities müssen in beiden Deployments versioniert oder als
   gemeinsames Paket konsumiert werden.
5. Deployments werden getrennt geprüft; Core darf keine Premium-Logik enthalten.
