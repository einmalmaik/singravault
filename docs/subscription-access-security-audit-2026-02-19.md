# Subscription Access Security Audit (2026-02-19)

## Scope

- Emergency Access entitlement enforcement
- Post-Quantum protection for sharing keys availability by tier
- Pricing page feature claims
- File attachment security and quota controls (1 GB target)
- Vault item creation failure path in `VaultItemDialog.tsx`

## Findings

1. Emergency Access was enforced mainly client-side.
2. Post-Quantum sharing-key protection feature matrix marked `post_quantum_encryption` as paid-only.
3. Pricing page explicitly listed Post-Quantum sharing-key protection as a Premium card bullet.
4. File attachment limits were primarily client-enforced; DB had no hard 1 GB aggregate guard.
5. `resolveDefaultVaultId()` used `maybeSingle()`, which is brittle for multi-row defaults and can fail noisy in edge states.

## Implemented Changes

### 1) Emergency Access restricted to paid tiers (Premium/Families)

- Added UI gate:
  - `src/components/settings/EmergencyAccessSettings.tsx`
  - Wrapped content in `FeatureGate feature="emergency_access"`.
- Added Edge Function entitlement check:
  - `supabase/functions/invite-emergency-access/index.ts`
  - Enforces `subscriptions.tier IN ('premium','families')` and `status IN ('active','trialing')`.
- Added DB/RLS enforcement:
  - `supabase/migrations/20260219143000_enforce_paid_emergency_and_attachment_limits.sql`
  - Replaced insert policy with paid-tier check.

### 2) Post-Quantum sharing-key protection available to all users (including free)

- Updated feature matrix:
  - `src/config/planConfig.ts`
  - `post_quantum_encryption: { free: true, premium: true, families: true }`.

### 3) Remove Post-Quantum sharing-key mention from Pricing page

- Removed `subscription.features.post_quantum` from Premium feature list:
  - `src/pages/PricingPage.tsx`

### 4) 1 GB attachment security hardening (zero-knowledge aligned)

- Added DB trigger enforcement:
  - `supabase/migrations/20260219143000_enforce_paid_emergency_and_attachment_limits.sql`
- Enforced server-side:
  - `<= 100 MB` per file
  - `<= 1 GB` total per user
  - user-owned `vault_item_id` only
  - `storage_path` must be namespaced by `user_id`
  - `encrypted = true`
  - paid-tier required on insert
- Existing zero-knowledge posture remains:
  - content encrypted client-side before upload
  - metadata encrypted in `encrypted_metadata`
  - private storage bucket + owner-scoped storage policies

### 5) Vault item creation robustness (`VaultItemDialog.tsx:429` path)

- Strengthened default vault resolution:
  - `src/services/offlineVaultService.ts`
  - `resolveDefaultVaultId()` now uses ordered `select + limit(1)` instead of `maybeSingle()`.
- Improved save payload correctness:
  - `src/components/vault/VaultItemDialog.tsx`
  - Persist actual `item_type`, `is_favorite`, `category_id`.
- Improved error visibility:
  - toast now surfaces concrete error message when available.
- Prevented attachment subcomponent mount during new-item creation:
  - only render `FileAttachments` when `itemId` exists.

## Test Updates

- `src/hooks/useFeatureGate.test.tsx`
- `src/hooks/__tests__/useFeatureGate.test.tsx`
- `src/test/unit-pure-functions.test.ts`

Adjusted for Post-Quantum sharing-key protection now being a free feature.

## Security Notes

- Entitlements must be enforced server-side; client gates are UX-only.
- Quota checks are now guaranteed at DB layer (not bypassable via direct API calls).
- Attachment bytes and metadata remain encrypted client-side (zero-knowledge preserving).
