-- Copyright (c) 2025-2026 Maunting Studios
-- Licensed under the Business Source License 1.1 - see LICENSE
--
-- Migration: Add encrypted_user_key column to profiles
--
-- Introduces the User Symmetric Key (USK) layer, inspired by Bitwarden's
-- layered key architecture.
--
-- ARCHITECTURE:
--   Argon2id(password, encryption_salt) → kdfOutputBytes (32 B)
--       HKDF-Expand(kdfOutputBytes, info="singra-vault-wrap-v1") → wrapKey (32 B)
--       AES-256-GCM(randomUSK, wrapKey) → encrypted_user_key (this column)
--       randomUSK → encrypts vault items, RSA private key, PQ private key
--
-- BENEFITS:
--   1. Password change: only re-wraps this 32-byte blob — no vault re-encryption
--   2. HKDF domain separation: raw KDF output is never directly an encryption key
--   3. Unified key hierarchy: RSA and PQ private keys share the USK as wrap key
--
-- MIGRATION STRATEGY:
--   - NULL = pre-USK user, not yet migrated
--   - Migration happens transparently on the user's next unlock (client-side)
--   - No server-side backfill needed — client derives the deterministic
--     initial USK from the same KDF output that encrypted existing vault items,
--     so no vault re-encryption is required on migration
--
-- FORMAT:
--   base64(IV(12 bytes) || AES-256-GCM-ciphertext || auth-tag(16 bytes))
--   Decrypted payload: base64-encoded 32-byte UserKey

ALTER TABLE public.profiles
    ADD COLUMN IF NOT EXISTS encrypted_user_key TEXT DEFAULT NULL;

COMMENT ON COLUMN public.profiles.encrypted_user_key IS
    'UserKey (32-byte AES-256) encrypted with HKDF-derived wrap key. '
    'Format: base64(IV(12)||ciphertext||tag(16)). '
    'NULL = pre-USK user, migrated transparently on next client unlock.';
