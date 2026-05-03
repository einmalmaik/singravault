## Scope

Security hardening updates applied on February 18, 2026.

## Changes

1. Passkey PRF activation persistence moved to server-side WebAuthn action `activate-prf`.
2. Client-side direct write to `passkey_credentials.wrapped_master_key` removed from `activatePasskeyPrf`.
3. Key material provisioning race hardening:
   - `ensureUserRsaKeyMaterial` now uses insert + unique-conflict winner re-read.
   - `ensureUserPqKeyMaterial` now uses conditional update/insert + winner re-read.
4. RSA private key envelope format updated to `kdfVersion:salt:encryptedData` with legacy `salt:encryptedData` support in `unwrapKey`.
5. Hybrid key combiner updated from XOR to HKDF-SHA-256 with ciphertext-bound context (`Singra Vault-HybridKDF-v1`).
6. `SECURITY_STANDARD_VERSION` centralized in `src/services/securityStandard.ts`.
7. Password verifier format updated to randomised `v2` payloads (legacy verifier format remains readable).

## Verification Focus

1. PRF activation path now requires successful server-side authentication verification before key persistence.
2. Concurrent first-login key provisioning no longer overwrites previously written key material.
3. Existing legacy encrypted RSA private keys remain decryptable.
