// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Post-Quantum key-wrapping adapter for Singra Vault sharing flows.
 *
 * Powered by DIS — Defensive Integration Shield.
 *
 * This module contains NO cryptography of its own. The hybrid key-wrapping
 * implementation — ML-KEM-768 (FIPS 203) post-quantum KEM combined with
 * RSA-4096-OAEP, the versioned wire format (0x01–0x04) and the HKDF derivation —
 * now lives in the audited `@msdis/shield` package and is exercised by DIS's
 * golden-vector byte-compatibility gate. This file is a thin, stable re-export
 * so the rest of the app keeps importing `services/pqCryptoService` unchanged.
 *
 * In the product threat model this protects sharing and emergency-access keys
 * against "harvest now, decrypt later" attacks. It is not the encryption layer
 * for vault item payloads. Do NOT add crypto here — add it to @msdis/shield.
 *
 * @see https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
 * @see https://github.com/einmalmaik/dis
 */

export * from '@msdis/shield/post-quantum';
