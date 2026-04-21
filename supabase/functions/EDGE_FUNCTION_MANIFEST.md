# Edge Function Manifest — Open Core Split

Dieses Manifest definiert, welche Edge Functions zum öffentlichen Core und welche zum privaten Premium-Paket (`@singra/premium`) gehören.

## Core Functions (öffentlich)

Diese Functions bleiben im `singra-vault` Repository:

| Function | Zweck |
|----------|-------|
| `auth-opaque` | OPAQUE-Protokoll Login |
| `auth-register` | Benutzerregistrierung |
| `auth-recovery` | Account-Wiederherstellung |
| `auth-reset-password` | Passwort zurücksetzen |
| `auth-session` | Session-Management + 2FA-Verifikation |
| `webauthn` | Passkey/WebAuthn-Operationen |
| `rate-limit` | Rate-Limiting |
| `admin-team` | Team-Rollen & Permissions |

## Premium Functions (privat → `@singra/premium`)

Diese Functions werden beim Repo-Split ins private Repository verschoben.
Jede ist mit `// @premium` im Quellcode markiert.

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

### Support-System

| Function | Zweck |
|----------|-------|
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

## Repo-Split Anleitung

1. Alle Functions mit `// @premium` Header → ins Premium-Repo kopieren
2. `supabase/config.toml` aufteilen (Core behält nur Core-Einträge)
3. Premium-Repo bekommt eigenes `supabase/config.toml` mit den Premium-Einträgen
4. `_shared/cors.ts` in beiden Repos vorhalten (oder als npm-Paket)
5. Deploy: Beide Repos deployen zum selben Supabase-Projekt
