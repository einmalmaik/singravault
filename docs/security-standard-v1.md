# Security Standard v1

## Summary

Security Standard v1 enforces hybrid key exchange for shared and emergency flows:

1. ML-KEM-768 (post-quantum KEM)
2. RSA-4096 (classical asymmetric layer)
3. HKDF-SHA-256 key combination (v2: both secrets as IKM, zero-byte salt, `Singra Vault-HybridKDF-v2:` info)

Vault payload encryption remains AES-256-GCM with Argon2id-derived keys.

## Enforcement

1. Runtime decryption for hybrid ciphertext accepts versions `0x03` (HKDF-v1, legacy) and `0x04` (HKDF-v2, current).
2. New encryptions always produce version `0x04`.
3. Legacy RSA-only key exchange paths are blocked in application services.
4. Shared collection and emergency setup flows require PQ key material.

## Profile Metadata

`profiles` now carries rollout state:

1. `security_standard_version`
2. `legacy_crypto_disabled_at`
3. `pq_enforced_at`

These values are set during key-material provisioning.

## Database Guardrails

Migration `20260217213000_security_standard_v1_profiles_and_hybrid_constraints.sql` adds:

1. Profile metadata columns and indexes.
2. Constraint checks (added `NOT VALID`) to enforce PQ fields on new writes.

Migration `20260217230000_validate_security_standard_v1_constraints.sql` finalizes rollout:

1. Validates Security Standard v1 check constraints.
2. Enforces `collection_keys.wrapped_key = collection_keys.pq_wrapped_key` for compatibility mirror semantics.

## Compatibility Notes

1. Existing data can still be detected and migrated with dedicated migration helpers.
2. Runtime business logic now treats non-v1 key exchange payloads as non-compliant.
