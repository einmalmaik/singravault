# Subscription System Documentation

## Overview

Singra Vault offers three subscription tiers: **FREE**, **PREMIUM**, and **FAMILIES**. The billing system integrates Stripe for payment processing and complies with German/EU consumer protection laws.

## Tiers & Features

| Feature | FREE | PREMIUM | FAMILIES |
|---|:---:|:---:|:---:|
| Unlimited Passwords | ✅ | ✅ | ✅ |
| Device Sync | ✅ | ✅ | ✅ |
| Password Generator | ✅ | ✅ | ✅ |
| Secure Notes | ✅ | ✅ | ✅ |
| External 2FA | ✅ | ✅ | ✅ |
| Post-Quantum Protection for Sharing Keys | ✅ | ✅ | ✅ |
| Passkey Vault Unlock (PRF) | ✅ | ✅ | ✅ |
| Vault Integrity Check | ✅ | ✅ | ✅ |
| 1 GB File Attachments | ❌ | ✅ | ✅ |
| Built-in Authenticator | ❌ | ✅ | ✅ |
| Duress Password | ❌ | ✅ | ✅ |
| Emergency Access | ❌ | ✅ | ✅ |
| Vault Health Reports | ❌ | ✅ | ✅ |
| Priority Support | ❌ | ✅ | ✅ |
| First Response Target | ~72h | ~24h | ~24h (Owner + active members) |
| 6 Premium Accounts | ❌ | ❌ | ✅ |
| Shared Collections | ❌ | ❌ | ✅ |

## Pricing

| Plan | Monthly | Yearly |
|---|---|---|
| Premium | €1.65/mo | €19.80/yr (2 months free) |
| Families | €3.99/mo | €47.88/yr (2 months free) |

**Introductory Discount:** 50% off the first month (monthly plans only, one-time per account).

## Architecture

### Data Flow

```
┌──────────┐     ┌─────────────────────┐     ┌────────────┐
│  Client   │────▶│  Supabase Edge Fn   │────▶│   Stripe   │
│ (React)   │◀────│  (JWT + plan_key)   │◀────│  (Billing)  │
└──────────┘     └─────────────────────┘     └────────────┘
                          │                         │
                          ▼                         │
                  ┌───────────────┐                 │
                  │  Supabase DB   │◀───────────────┘
                  │ (subscriptions)│    (via webhook)
                  └───────────────┘
```

### Key Design Decisions

1. **Server-side price validation:** Client sends symbolic `plan_key` (e.g., `premium_monthly`), server resolves to Stripe Price IDs via the private Premium package configuration. Client never determines prices.

2. **Webhook-driven state sync:** Subscription status in the database is updated exclusively through Stripe webhooks, ensuring consistency.

3. **Self-hosting mode:** Set `VITE_DISABLE_BILLING=true` to unlock all features without Stripe.

4. **Support SLA tracking:** First-response metrics are tracked server-side (`sla_due_at`, `first_response_at`, `first_response_minutes`) to measure current average response times and SLA hit-rate.

### Edge Functions

| Function | Auth | Purpose |
|---|---|---|
| `create-checkout-session` | JWT | Creates Stripe Checkout session with Widerruf validation |
| `stripe-webhook` | Stripe Signature | Syncs subscription state from Stripe events |
| `create-portal-session` | JWT | Opens Stripe Customer Portal |
| `cancel-subscription` | JWT | Cancels subscription at period end |

### Database Tables

- `subscriptions` — Core subscription data (tier, status, Stripe IDs, period end)
- `emergency_access` — Trusted contacts for account recovery (PREMIUM+)
- `file_attachments` — Encrypted file metadata (PREMIUM+)
- `family_members` — Family group management (FAMILIES)
- `shared_collections` — Shared vault collections (FAMILIES)

## Legal Compliance (Germany / EU)

### Right of Withdrawal (§355 BGB)

Before checkout, users must accept two mandatory checkboxes:

1. **Consent to early execution:** "Ich verlange ausdrücklich, dass ihr mit der Ausführung des Vertrages vor Ablauf der Widerrufsfrist beginnt."
2. **Acknowledgment of loss:** "Mir ist bekannt, dass ich bei vollständiger Vertragserfüllung mein Widerrufsrecht verliere."

Both are validated server-side in `create-checkout-session`.

### Online Cancellation (§312k BGB)

A prominent "Jetzt kündigen" button is placed in Settings with a two-step confirmation:
1. User clicks cancel button
2. Confirmation dialog explains consequences
3. Subscription canceled at period end (access retained until then)

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `STRIPE_API_KEY` | Yes | Stripe secret key (live or test) |
| `STRIPE_WEBHOOK_SECRET` | Yes* | Stripe webhook signing secret |
| `VITE_DISABLE_BILLING` | No | Set `true` to disable billing (self-host) |
| `VITE_SUPABASE_URL` | Yes | Supabase project URL |
| `VITE_SUPABASE_PUBLISHABLE_KEY` | Yes | Supabase anon/publishable key |

*Required as Supabase Edge Function secret.

## Setup

### 1. Stripe Webhook Configuration

1. Go to Stripe Dashboard → Developers → Webhooks
2. Add endpoint: `https://<project-ref>.supabase.co/functions/v1/stripe-webhook`
3. Select events:
   - `checkout.session.completed`
   - `invoice.payment_succeeded`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Copy the signing secret
5. Add to Supabase secrets: `supabase secrets set STRIPE_WEBHOOK_SECRET=whsec_...`

### 2. Stripe Customer Portal

Configure the portal in Stripe Dashboard → Settings → Billing → Customer Portal:
- Enable invoice history
- Enable payment method management
- Disable plan changes (we handle these in-app)

## Self-Hosting

Set `VITE_DISABLE_BILLING=true` in your `.env` file. This:
- Unlocks all PREMIUM features for all users
- Hides pricing page, subscription settings, and upgrade prompts
- Removes all Stripe integration code paths
