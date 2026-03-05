# Subscription E-Mail Notifications (2026-03-05)

## Übersicht
- E-Mail-Benachrichtigungen bei Abo-Kauf und Kündigung über Resend API
- E-Mail-Templates in `src/email-templates/` (subscription-confirmed.html, subscription-canceled.html)
- Stripe Webhook (`stripe-webhook/index.ts`) sendet E-Mails automatisch

## Trigger
| Event | E-Mail |
|-------|--------|
| `checkout.session.completed` | Bestätigung mit Plan-Name |
| `customer.subscription.updated` (cancel_at_period_end=true) | Kündigung mit Enddatum |

## Weitere Änderungen
- `feature_locked_title` umbenannt zu "Premium / Family Funktion"
- Toast auf SettingsPage bei `?checkout=success` / `?checkout=cancel`
- `return_url` in create-checkout-session für korrekte Redirects
