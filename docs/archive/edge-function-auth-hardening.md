# Edge Function Auth Hardening (February 2026)

## Summary

This change hardens client to Edge Function calls that require authenticated users:

- Added `src/services/edgeFunctionService.ts` as a single JWT-enforced invocation path.
- Added normalized error metadata (`status`, `code`) for consistent UI handling.
- Migrated critical flows to explicit bearer tokens:
  - Family invitation
  - Emergency access invitation
  - WebAuthn passkey actions

## Why

Production logs showed `401` responses on selected functions while other functions succeeded in the same session.  
Root cause was inconsistent token forwarding for function calls.

## Behavioral changes

- Session/auth errors now surface as explicit user-facing errors instead of silent fallbacks.
- Passkey listing no longer silently returns an empty list on function auth failures.
- Family and emergency invite success messaging now clearly states:
  - invitees can register first if the email is not yet registered.

## Edge Function diagnostics

The following functions now include structured log context for faster incident triage:

- `supabase/functions/invite-family-member/index.ts`
- `supabase/functions/invite-emergency-access/index.ts`

## Validation scope

Recommended targeted checks:

```bash
npx vitest run src/services/edgeFunctionService.test.ts
npx vitest run src/services/__tests__/familyService.test.ts
npx vitest run src/services/__tests__/emergencyAccessService.test.ts
npx vitest run src/components/settings/__tests__/PasskeySettings.test.tsx
```
