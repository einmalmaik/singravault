# Post-Quantum Default Path (Sharing + Emergency)

## Overview

This change set makes hybrid post-quantum protection the default write path for wrapping sharing-related keys:

1. Shared Collections key exchange
2. Emergency Access key exchange

Hybrid means ML-KEM-768 + RSA-4096 for key wrapping/key exchange. Vault item payloads continue to use AES-256-GCM with user-derived symmetric keys.

## Why

The previous UI flow could fail for accounts without pre-provisioned `user_keys` rows and relied on browser `window.prompt` for master password input in one path.

## What changed

1. Added `src/services/keyMaterialService.ts`:
   - `ensureUserRsaKeyMaterial(...)`
   - `ensureUserPqKeyMaterial(...)`
   - `ensureHybridKeyMaterial(...)`
   - `isMasterPasswordRequiredError(...)`
2. Shared Collections creation now:
   - uses `ensureHybridKeyMaterial(...)`
   - uses controlled password dialog (no `window.prompt`)
   - writes new collection member keys via hybrid wrapping
3. Passkey PRF activation now targets a specific credential ID:
   - client sends expected credential
   - edge function scopes options and validates credential use
4. Emergency Access flow now checks profile update errors explicitly and provisions hybrid material during setup when a master key must be wrapped for a trustee.
5. Added `pq_enforced_at` to generated Supabase types.

## Compatibility

1. New sharing/emergency key-wrap writes are hybrid-first.
2. Existing legacy RSA read paths remain for compatibility.

## Validation

Validated with:

1. Targeted ESLint on changed files
2. Vitest suites for:
   - `keyMaterialService`
   - `PasskeySettings`
   - `collectionService`
   - `emergencyAccessService`
3. Production build (`npm run build`)

## Security Standard v1

Follow-up hardening is documented in `docs/security-standard-v1.md`:

1. Hybrid wrapped-key version v3 enforcement
2. Legacy RSA-only flow blocking
3. Profile metadata for rollout and auditability
