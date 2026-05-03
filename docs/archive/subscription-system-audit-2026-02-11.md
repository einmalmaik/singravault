# Subscription System Audit (2026-02-11)

## Ziel
- Vollständige Prüfung des Abo-Systems (Client + Edge Functions + DB-Verhalten auf Code-Ebene).
- Absicherung durch neue Unit- und Integration-Tests.
- Fokus auf Zuverlässigkeit, Konsistenz und sichere Zustandsübergänge.

## Durchgeführte Änderungen

### 1) Reliability Fix: Logout-State im Subscription Context
- Datei: `src/contexts/SubscriptionContext.tsx`
- Problem: Beim Logout wurde `subscription` nicht explizit auf `null` gesetzt.
- Risiko: Potenziell stale UI-State nach User-Wechsel.
- Fix: Bei `!user || BILLING_DISABLED` wird jetzt `setSubscription(null)` gesetzt.

### 2) Reliability Fix: Redirect ohne Side-Effect im Render
- Datei: `src/pages/PricingPage.tsx`
- Problem: `navigate('/settings')` wurde direkt im Render ausgeführt.
- Risiko: React-Side-Effect im Renderpfad (instabil, schwer testbar).
- Fix: Umstellung auf `<Navigate to="/settings" replace />`.

### 3) Konsistenzfix Intro-Rabatt (monatlich-only)
- Dateien:
  - `supabase/functions/create-checkout-session/index.ts`
  - `src/components/Subscription/CheckoutDialog.tsx`
  - `src/pages/PricingPage.tsx`
- Problem: Doku sagt "50% im ersten Monat", Code zeigte/anwendete Rabatt auch für jährliche Pläne.
- Risiko: Inkonsistente Preislogik zwischen Doku/UI/Backend.
- Fix:
  - Backend-Coupon nur noch bei `plan_key.endsWith("_monthly")`.
  - Rabatt-Hinweis in UI nur noch für monatliche Pläne.

## Neue Tests

### Unit-Tests
- `src/services/subscriptionService.test.ts`
- Abgedeckt:
  - `getSubscription` ohne User
  - `getSubscription` mit User/DB-Daten
  - `createCheckoutSession` Consent-Gating (Widerruf)
  - `createCheckoutSession` Erfolgsfall
  - `createPortalSession` Fehlerpfad
  - `cancelSubscription` Fehlerpfad
  - `cancelSubscription` Erfolgs-Mapping

### Integration-Tests (UI/Context)
- `src/contexts/SubscriptionContext.test.tsx`
- Abgedeckt:
  - Laden und Feature-Freigaben für aktives Premium
  - Feature-Sperre bei inaktivem Paid-Status
  - Reset auf Free-State nach Logout (stale-access Prävention)

- `src/components/Subscription/CheckoutDialog.test.tsx`
- Abgedeckt:
  - Checkout nur mit beiden Pflicht-Checkboxen
  - Rabattanzeige nur für Monatsplan
  - Fehleranzeige bei Checkout-Fehlern

### Risiko-Tests (direkt auf offene Punkte)
- `src/test/subscription-risk-assessment.test.ts`
- Abgedeckt:
  - **Parallele Checkout-Flows**: Zwei gleichzeitige Requests an `create-checkout-session` für denselben User/Plan.
  - **Webhook-Idempotenz-Lücke**: Automatischer Nachweis, dass kein dediziertes Event-Dedupe-Persistenzmuster (`processed_webhook_events`/`event_id`-Uniqueness) in Funktion + Migration existiert.

## Testausführung

### Gezielter Lauf (neue Abo-Tests)
- Befehl:
  - `npm run test -- src/services/subscriptionService.test.ts src/contexts/SubscriptionContext.test.tsx src/components/Subscription/CheckoutDialog.test.tsx`
- Ergebnis:
  - **13/13 Tests bestanden**

### Gezielter Lauf (offene Risiko-Punkte)
- Befehl:
  - `npm run test -- src/test/subscription-risk-assessment.test.ts`
- Ergebnis:
  - **2/2 Tests bestanden**
  - Parallel-Checkout-Test lieferte zwei erfolgreiche, unterschiedliche Checkout-URLs für denselben User/Plan.
  - Damit ist das Risiko "kein expliziter Schutz gegen parallele/doppelte Checkout-Flows" reproduzierbar bestätigt.

### Vollständige Suite
- Befehl:
  - `npm run test`
- Ergebnis:
  - Neue Abo-Tests: **grün**
  - Bestehende Fremdtests: **2 Fehler in `src/test/key-rotation.test.ts`**
  - Fehlerbild: FK-Verletzung (`user_2fa_user_id_fkey`) mit nicht vorhandenen Test-User-IDs.

## Offene Risiken (Abo-Logik)
- Kein idempotentes Event-Tracking im Stripe-Webhook (z. B. `processed_webhook_events`).
- Kein expliziter Schutz gegen parallele/doppelte aktive Checkout-Flows im `create-checkout-session`-Pfad.

## Externe Referenz (MCP/Perplexity)
- Perplexity Ask wurde genutzt, um aktuelle Testschwerpunkte für Subscription-Billing (Edge Cases, Race Conditions, Lifecycle-Tests) abzugleichen.
