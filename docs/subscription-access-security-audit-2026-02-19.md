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
  - legacy state at the time: `<= 100 MB` per file and `<= 1 GB` total per user
  - superseded on 2026-04-26 by `supabase/migrations/20260426143000_file_attachment_e2ee_chunked_limits.sql`: chunked E2EE supports 1 GB plaintext files with a 2 GB technical ciphertext budget
  - user-owned `vault_item_id` only
  - `storage_path` must be namespaced by `user_id`
  - `encrypted = true`
  - paid-tier required on insert
- Existing zero-knowledge posture remains:
  - content encrypted client-side before upload
  - a random file key is generated per file and wrapped with the locally unlocked vault/UserKey
  - each chunk is AES-256-GCM encrypted with its own nonce and AAD
  - metadata is stored only in the encrypted, authenticated `sv-file-manifest-v1` manifest
  - manifest revisions, manifest roots, previous-manifest hashes, and local last-seen checkpoints detect rollback when a trusted previous state exists
  - downloads stream decrypted chunks to File System Access API writers on supported browsers and to temporary Tauri/Desktop files; unsupported browsers use a documented Blob fallback
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
- Attachment bytes and metadata remain encrypted client-side (zero-knowledge preserving). Server-visible metadata is limited to owner binding, opaque paths, timestamps, ciphertext sizes, chunk/object counts, and access patterns.
- There is no true cross-session upload resume yet. Failed uploads remove chunks uploaded in the current session; a browser/app crash can leave orphaned encrypted chunks until storage cleanup is introduced.
