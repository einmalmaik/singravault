// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Unit tests for the User Symmetric Key (USK) layer.
 *
 * Covers:
 *   - createEncryptedUserKey / unwrapUserKey roundtrip
 *   - migrateToUserKey determinism
 *   - rewrapUserKey: old kdfOutput can no longer unwrap after rewrap
 *   - wrapPrivateKeyWithUserKey / unwrapPrivateKeyWithUserKey roundtrip
 *   - getDecryptedRsaPrivateKey / getDecryptedPqPrivateKey dispatcher
 *   - decryptPrivateKeyLegacy format handling
 */

import { describe, it, expect } from 'vitest';
import {
  createEncryptedUserKey,
  migrateToUserKey,
  unwrapUserKey,
  rewrapUserKey,
  wrapPrivateKeyWithUserKey,
  unwrapPrivateKeyWithUserKey,
  getDecryptedRsaPrivateKey,
  getDecryptedPqPrivateKey,
  decryptPrivateKeyLegacy,
  deriveRawKey,
  encrypt,
  generateSalt,
} from '@/services/cryptoService';

// ─── Helpers ───────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function generateTestKdfOutput(): Uint8Array {
  // High-entropy 32-byte blob simulating Argon2id output
  return randomBytes(32);
}

// ─── Tests ─────────────────────────────────────────────────────────────────

describe('USK Layer — createEncryptedUserKey / unwrapUserKey', () => {
  it('roundtrip: unwrapUserKey returns a non-extractable CryptoKey', async () => {
    const kdfOutputBytes = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdfOutputBytes);

    expect(typeof bundle.encryptedUserKey).toBe('string');
    expect(bundle.encryptedUserKey.length).toBeGreaterThan(0);
    expect(bundle.encryptedUserKey.startsWith('usk-wrap-v2:')).toBe(true);

    const recovered = await unwrapUserKey(bundle.encryptedUserKey, kdfOutputBytes);
    expect(recovered.type).toBe('secret');
    expect(recovered.extractable).toBe(false);
    expect(recovered.usages).toContain('encrypt');
    expect(recovered.usages).toContain('decrypt');
  });

  it('different kdfOutputBytes produce different encryptedUserKey blobs', async () => {
    const kdf1 = generateTestKdfOutput();
    const kdf2 = generateTestKdfOutput();
    const b1 = await createEncryptedUserKey(kdf1);
    const b2 = await createEncryptedUserKey(kdf2);
    expect(b1.encryptedUserKey).not.toBe(b2.encryptedUserKey);
  });

  it('unwrapUserKey throws when given wrong kdfOutputBytes', async () => {
    const kdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdf);
    const wrongKdf = generateTestKdfOutput();
    await expect(unwrapUserKey(bundle.encryptedUserKey, wrongKdf)).rejects.toThrow();
  });
});

describe('USK Layer — migrateToUserKey', () => {
  it('is deterministic: same kdfOutput → same encryptedUserKey payload decrypts consistently', async () => {
    const kdf = generateTestKdfOutput();
    const bundle1 = await migrateToUserKey(kdf);
    const bundle2 = await migrateToUserKey(kdf);

    // The encryptedUserKey blobs may differ (different IVs per encrypt call),
    // but both must unwrap successfully with the same kdf.
    const key1 = await unwrapUserKey(bundle1.encryptedUserKey, kdf);
    const key2 = await unwrapUserKey(bundle2.encryptedUserKey, kdf);

    // Both keys should be able to encrypt/decrypt the same plaintext identically.
    const plaintext = 'migration-determinism-test';
    const enc1 = await encrypt(plaintext, key1);
    const enc2 = await encrypt(plaintext, key2);
    // Ciphertexts may differ (different IVs) but both should decrypt correctly.
    // We verify by decrypting enc1 with key2 — they must be the same underlying key bytes.
    const { decrypt } = await import('@/services/cryptoService');
    const dec1with2 = await decrypt(enc1, key2);
    const dec2with1 = await decrypt(enc2, key1);
    expect(dec1with2).toBe(plaintext);
    expect(dec2with1).toBe(plaintext);
  });

  it('migrateToUserKey and createEncryptedUserKey derive DIFFERENT user keys from the same kdf', async () => {
    const kdf = generateTestKdfOutput();
    const migBundle = await migrateToUserKey(kdf);
    const newBundle = await createEncryptedUserKey(kdf);

    const migKey = await unwrapUserKey(migBundle.encryptedUserKey, kdf);
    const newKey = await unwrapUserKey(newBundle.encryptedUserKey, kdf);

    // Verify they produce different ciphertexts — hence different keys
    const { decrypt } = await import('@/services/cryptoService');
    const plaintext = 'cross-key-isolation-test';
    const encWithMig = await encrypt(plaintext, migKey);
    // Decrypting with newKey should throw or produce garbage
    let crossDecryptFailed = false;
    try {
      await decrypt(encWithMig, newKey);
    } catch {
      crossDecryptFailed = true;
    }
    expect(crossDecryptFailed).toBe(true);
  });
});

describe('USK Layer — rewrapUserKey', () => {
  it('rewrapped key can be unwrapped with new kdf but not old kdf', async () => {
    const oldKdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(oldKdf);

    const newKdf = generateTestKdfOutput();
    const rewrapped = await rewrapUserKey(bundle.encryptedUserKey, oldKdf, newKdf);
    expect(rewrapped.startsWith('usk-wrap-v2:')).toBe(true);

    // Must succeed with newKdf
    const recoveredKey = await unwrapUserKey(rewrapped, newKdf);
    expect(recoveredKey.type).toBe('secret');

    // Must fail with oldKdf
    await expect(unwrapUserKey(rewrapped, oldKdf)).rejects.toThrow();
  });

  it('the underlying user key bytes are preserved across rewrap', async () => {
    const oldKdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(oldKdf);
    const originalKey = await unwrapUserKey(bundle.encryptedUserKey, oldKdf);

    const newKdf = generateTestKdfOutput();
    const rewrapped = await rewrapUserKey(bundle.encryptedUserKey, oldKdf, newKdf);
    const rewrappedKey = await unwrapUserKey(rewrapped, newKdf);

    // Both should encrypt/decrypt the same plaintext
    const { decrypt } = await import('@/services/cryptoService');
    const plaintext = 'rewrap-key-preservation-test';
    const encWithOriginal = await encrypt(plaintext, originalKey);
    const decWithRewrapped = await decrypt(encWithOriginal, rewrappedKey);
    expect(decWithRewrapped).toBe(plaintext);
  });
});

describe('USK Layer — wrapPrivateKeyWithUserKey / unwrapPrivateKeyWithUserKey', () => {
  it('roundtrip preserves the plaintext private key material', async () => {
    const kdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdf);
    const plainPrivateKey = '{"kty":"RSA","n":"test-modulus","e":"AQAB"}';

    const wrapped = await wrapPrivateKeyWithUserKey(plainPrivateKey, bundle.userKey);
    const unwrapped = await unwrapPrivateKeyWithUserKey(wrapped, bundle.userKey);

    expect(unwrapped).toBe(plainPrivateKey);
  });

  it('wrapped ciphertext is base64 and does not contain plaintext', async () => {
    const kdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdf);
    const plainPrivateKey = '{"kty":"RSA","n":"test-modulus","e":"AQAB"}';

    const wrapped = await wrapPrivateKeyWithUserKey(plainPrivateKey, bundle.userKey);
    // Output must be the sentinel prefix + a valid base64 string
    expect(wrapped.startsWith('usk-v1:')).toBe(true);
    const cipherBase64 = wrapped.slice('usk-v1:'.length);
    expect(() => atob(cipherBase64)).not.toThrow();
    // Plaintext must not appear in the ciphertext
    expect(wrapped).not.toContain('RSA');
    expect(wrapped).not.toContain('test-modulus');
  });
});

describe('USK Layer — getDecryptedRsaPrivateKey dispatcher', () => {
  it('dispatches usk-v1: format via UserKey (ignores masterPassword)', async () => {
    const kdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdf);
    const plainKey = '{"kty":"RSA","n":"modulus","e":"AQAB","d":"private"}';

    // wrapPrivateKeyWithUserKey already includes the usk-v1: prefix
    const stored = await wrapPrivateKeyWithUserKey(plainKey, bundle.userKey);

    const result = await getDecryptedRsaPrivateKey(stored, bundle.userKey, 'any-password');
    expect(result).toBe(plainKey);
  });

  it('throws for usk-v1: format when userKey is null', async () => {
    const stored = 'usk-v1:someBase64Ciphertext';
    await expect(getDecryptedRsaPrivateKey(stored, null, 'password')).rejects.toThrow('UserKey required');
  });
});

describe('USK Layer — getDecryptedPqPrivateKey dispatcher', () => {
  it('dispatches usk-v1: format via UserKey (ignores masterPassword)', async () => {
    const kdf = generateTestKdfOutput();
    const bundle = await createEncryptedUserKey(kdf);
    const plainPqKey = 'base64-encoded-mlkem-secret-key-material';

    // wrapPrivateKeyWithUserKey already includes the usk-v1: prefix
    const stored = await wrapPrivateKeyWithUserKey(plainPqKey, bundle.userKey);

    const result = await getDecryptedPqPrivateKey(stored, bundle.userKey, 'any-password');
    expect(result).toBe(plainPqKey);
  });

  it('throws for usk-v1: format when userKey is null', async () => {
    const stored = 'usk-v1:someBase64Ciphertext';
    await expect(getDecryptedPqPrivateKey(stored, null, 'password')).rejects.toThrow('UserKey required');
  });
});

describe('decryptPrivateKeyLegacy — format detection', () => {
  it('rejects malformed input (no colons)', async () => {
    await expect(decryptPrivateKeyLegacy('justaplainstring', 'pass')).rejects.toThrow();
  });

  it('rejects pq-v2: format without enough colons', async () => {
    await expect(decryptPrivateKeyLegacy('pq-v2:onlythree', 'pass')).rejects.toThrow();
  });

  // Note: actual KDF-based decryption tests require real Argon2id (WASM),
  // so we only test format detection / error paths here.
  // Integration tests cover the full KDF+decrypt roundtrip.
});

describe('USK Layer — key isolation between createEncryptedUserKey and migrateToUserKey', () => {
  it('new random USK and migration USK are different keys from the same kdfOutput', async () => {
    // createEncryptedUserKey uses a random USK (not derived from kdfOutput)
    // migrateToUserKey derives USK directly from raw kdfOutputBytes (pre-USK compat)
    // They must produce keys that cannot decrypt each other's ciphertexts
    const kdf = generateTestKdfOutput();
    const newBundle = await createEncryptedUserKey(kdf);
    const migBundle = await migrateToUserKey(kdf);

    // These bundles contain different user keys — cross-decryption must fail
    const { decrypt } = await import('@/services/cryptoService');
    const plaintext = 'domain-separation-test';
    const migKey = await unwrapUserKey(migBundle.encryptedUserKey, kdf);
    const newKey = await unwrapUserKey(newBundle.encryptedUserKey, kdf);

    const encWithMig = await encrypt(plaintext, migKey);
    let failed = false;
    try {
      await decrypt(encWithMig, newKey);
    } catch {
      failed = true;
    }
    expect(failed).toBe(true);
  });
});
