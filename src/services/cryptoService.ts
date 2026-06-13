// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Cryptographic Service adapter for Singra Vault.
 *
 * Powered by DIS — Defensive Integration Shield.
 *
 * This module contains NO cryptography of its own. Every primitive — Argon2id
 * key derivation, AES-256-GCM authenticated encryption, device-key HKDF
 * strengthening, the UserKey wrapping layer, RSA-OAEP and the versioned vault
 * data formats — now lives in the audited `@msdis/shield` package and is exercised
 * by DIS's golden-vector byte-compatibility gate. This file is a thin, stable
 * re-export so the rest of the app keeps importing `services/cryptoService`
 * unchanged while the implementation is owned centrally by DIS.
 *
 * SECURITY: The master password NEVER leaves the client; only encrypted data is
 * stored on the server. Do NOT add crypto here — add it to @msdis/shield and
 * re-export it through this adapter.
 *
 * @see https://github.com/einmalmaik/dis
 */

export * from '@msdis/shield/vault-crypto';
