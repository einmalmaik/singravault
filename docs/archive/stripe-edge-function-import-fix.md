# Fix: Stripe Edge Functions — esm.sh → npm: Import-Migration

**Datum:** 2026-02-25

## Problem

Alle 4 Stripe-bezogenen Edge Functions crashten beim Booten mit:

```
Deno.core.runMicrotasks() is not supported in this environment
```

**Ursache:** `https://esm.sh/stripe@17.7.0?target=deno` lädt Node.js-Polyfills, die in der Supabase Edge Runtime nicht unterstützt werden.

## Lösung

| Vorher | Nachher |
|--------|---------|
| `https://esm.sh/stripe@17.7.0?target=deno` | `npm:stripe@17.7.0` |
| `https://esm.sh/@supabase/supabase-js@2.49.1` | `npm:@supabase/supabase-js@2` |
| Statische `corsHeaders` | Dynamische `getCorsHeaders(req)` |

## Betroffene Dateien

- `supabase/functions/create-checkout-session/index.ts`
- `supabase/functions/cancel-subscription/index.ts`
- `supabase/functions/create-portal-session/index.ts`
- `supabase/functions/stripe-webhook/index.ts`

## Weitere Änderung (2026-02-25)

Alle 4 Stripe Edge Functions nutzen jetzt `STRIPE_SECRET_KEY` statt `STRIPE_API_KEY`, da `STRIPE_API_KEY` fälschlicherweise einen Publishable Key enthielt.

## Fix: auth-session esm.sh Migration (2026-02-25)

`auth-session/index.ts` nutzte ebenfalls `esm.sh` für `@supabase/supabase-js` und `serve` aus `deno.land/std`. Migriert auf `npm:@supabase/supabase-js@2` und `Deno.serve()`.

## Fix: Stale Stripe Customer ID (2026-02-25)

`create-checkout-session` validiert jetzt gespeicherte `stripe_customer_id` gegen die Stripe API. Falls der Customer nicht existiert (z.B. anderer Stripe-Account), wird automatisch ein neuer erstellt.

## Keine Logik-Änderungen

Stripe Price IDs, Widerruf-Validierung, Coupon-Logik und DB-Interaktionen blieben unverändert.
