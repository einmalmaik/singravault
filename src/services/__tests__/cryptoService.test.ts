// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Hardening tests for the central crypto boundary `cryptoService`.
 *
 * These tests pin down the contract that the rest of the vault — and any
 * Premium add-on that needs to encrypt vault-side data (e.g. images / file
 * attachments) — relies on. The goal is *not* to re-test the JS Web Crypto
 * implementation; the goal is to prove that the API surface in
 * `cryptoService.ts` keeps the following promises stable:
 *
 *   • AES-GCM round-trips for text and binary payloads
 *   • Each encrypt() call uses a fresh random IV (no reuse)
 *   • Decryption fails closed for wrong key / tampered ciphertext / wrong AAD
 *   • Vault item envelopes carry an explicit version prefix and unknown
 *     versions fail closed
 *   • UserKey wrapping/unwrapping is correct and tied to the wrap-key
 *   • KDF parameters for released versions stay byte-stable forever
 *   • Errors do not leak plaintext / key material into messages
 *
 * SECURITY: All keys, salts and "passwords" used here are synthetic test
 * fixtures. They MUST NOT resemble real user secrets and they live only in
 * memory inside the test.
 */

import { describe, expect, it } from "vitest";

import {
  CURRENT_KDF_VERSION,
  KDF_PARAMS,
  VAULT_ITEM_ENVELOPE_V1_PREFIX,
  createEncryptedUserKey,
  createVerificationHash,
  decrypt,
  decryptBytes,
  decryptVaultItem,
  decryptWithSharedKey,
  encrypt,
  encryptBytes,
  encryptVaultItem,
  encryptWithSharedKey,
  generateSalt,
  generateSharedKey,
  importMasterKey,
  isCurrentVaultItemEnvelope,
  rewrapUserKey,
  unwrapPrivateKeyWithUserKey,
  unwrapUserKey,
  unwrapUserKeyBytes,
  verifyKey,
  wrapPrivateKeyWithUserKey,
  type VaultItemData,
} from "@/services/cryptoService";

// ============================================================================
// Test fixtures — fast, deterministic, no real secrets
// ============================================================================

/** AES-256-GCM IV is 12 bytes, AES-256 key is 32 bytes — these are public. */
const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16; // 128-bit tag

const KEY_A_BYTES = new Uint8Array(KEY_LENGTH).fill(0x11);
const KEY_B_BYTES = new Uint8Array(KEY_LENGTH).fill(0x22);

async function loadKey(bytes: Uint8Array): Promise<CryptoKey> {
  return importMasterKey(bytes);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function flipByte(bytes: Uint8Array, index: number): Uint8Array {
  const copy = new Uint8Array(bytes);
  copy[index] ^= 0xff;
  return copy;
}

// ============================================================================
// 1. AES-GCM round-trip — text & binary
// ============================================================================

describe("cryptoService AES-GCM round-trip", () => {
  it("round-trips ASCII strings via encrypt/decrypt", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "synthetic ASCII fixture";

    const enc = await encrypt(plaintext, key);
    await expect(decrypt(enc, key)).resolves.toBe(plaintext);
  });

  it("round-trips Unicode + emoji + control characters", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "äöü ß — 日本語 — 🛡️\nline2\t<tab>\u0000<nul>";

    const enc = await encrypt(plaintext, key);
    await expect(decrypt(enc, key)).resolves.toBe(plaintext);
  });

  it("round-trips an empty string", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("", key);
    await expect(decrypt(enc, key)).resolves.toBe("");
  });

  it("round-trips a moderately large text payload (64 KiB)", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "A".repeat(64 * 1024);

    const enc = await encrypt(plaintext, key);
    await expect(decrypt(enc, key)).resolves.toBe(plaintext);
  });

  it("round-trips arbitrary binary bytes via encryptBytes/decryptBytes (premium attachment contract)", async () => {
    // Premium-Use-Case: image / file attachments must go through the same
    // central AES-GCM API. We assert here that arbitrary byte sequences
    // (including zero bytes and high bytes) round-trip exactly.
    const key = await loadKey(KEY_A_BYTES);
    const payload = new Uint8Array(1024);
    crypto.getRandomValues(payload);
    // Force a zero byte and a high byte so the payload is not all-random.
    payload[0] = 0x00;
    payload[1] = 0xff;

    const enc = await encryptBytes(payload, key);
    const round = await decryptBytes(enc, key);

    expect(round.byteLength).toBe(payload.byteLength);
    expect(Array.from(round)).toEqual(Array.from(payload));
  });

  it("encryptBytes preserves a synthetic PNG-ish header (binary attachment shape)", async () => {
    const key = await loadKey(KEY_A_BYTES);
    // Fixed bytes that resemble a small file-like prefix; not an actual PNG.
    const header = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const body = new Uint8Array(2048);
    crypto.getRandomValues(body);
    const payload = new Uint8Array(header.length + body.length);
    payload.set(header, 0);
    payload.set(body, header.length);

    const enc = await encryptBytes(payload, key);
    const round = await decryptBytes(enc, key);

    expect(Array.from(round.subarray(0, header.length))).toEqual(Array.from(header));
    expect(round.byteLength).toBe(payload.byteLength);
  });

  it("round-trips with AAD when the same AAD is supplied at decrypt-time", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "aad-bound";
    const aad = "vault-entry-7";

    const enc = await encrypt(plaintext, key, aad);
    await expect(decrypt(enc, key, aad)).resolves.toBe(plaintext);
  });
});

// ============================================================================
// 2. IV / nonce behaviour
// ============================================================================

describe("cryptoService IV/nonce behaviour", () => {
  it("produces distinct ciphertexts for the same plaintext + key (random IV)", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "iv-uniqueness-fixture";

    const ciphertexts = await Promise.all(
      Array.from({ length: 16 }, () => encrypt(plaintext, key)),
    );

    const distinct = new Set(ciphertexts);
    expect(distinct.size).toBe(ciphertexts.length);
  });

  it("emits a 12-byte IV prefix and an additional 16-byte authentication tag", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "iv-shape";
    const enc = await encrypt(plaintext, key);

    const raw = base64ToBytes(enc);
    const expectedMin = IV_LENGTH + TAG_LENGTH; // for an empty plaintext
    expect(raw.byteLength).toBeGreaterThanOrEqual(expectedMin);
    // The encoded plaintext is 8 bytes long → expected total = 12 + 8 + 16 = 36
    expect(raw.byteLength).toBe(IV_LENGTH + new TextEncoder().encode(plaintext).byteLength + TAG_LENGTH);
  });

  it("never leaks the plaintext as a substring of its ciphertext", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const plaintext = "PLAINTEXT_MARKER_DO_NOT_LEAK";

    const enc = await encrypt(plaintext, key);
    const raw = base64ToBytes(enc);
    const haystack = new TextDecoder("utf-8", { fatal: false }).decode(raw);

    expect(haystack).not.toContain(plaintext);
    // Also sanity-check the base64 form does not contain the literal marker.
    expect(enc).not.toContain(plaintext);
  });
});

// ============================================================================
// 3. Negative tests — fail-closed on wrong key / tampered data / wrong AAD
// ============================================================================

describe("cryptoService negative paths", () => {
  it("fails to decrypt with a different key", async () => {
    const keyA = await loadKey(KEY_A_BYTES);
    const keyB = await loadKey(KEY_B_BYTES);

    const enc = await encrypt("wrong-key", keyA);
    await expect(decrypt(enc, keyB)).rejects.toThrow();
  });

  it("fails when the ciphertext body is mutated", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("tamper-body", key);

    const raw = base64ToBytes(enc);
    // Flip a byte after the IV but before the tag (i.e. inside ciphertext).
    const tampered = bytesToBase64(flipByte(raw, IV_LENGTH + 1));
    await expect(decrypt(tampered, key)).rejects.toThrow();
  });

  it("fails when the IV bytes are mutated", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("tamper-iv", key);

    const raw = base64ToBytes(enc);
    const tampered = bytesToBase64(flipByte(raw, 0));
    await expect(decrypt(tampered, key)).rejects.toThrow();
  });

  it("fails when the GCM auth tag is mutated", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("tamper-tag", key);

    const raw = base64ToBytes(enc);
    const tampered = bytesToBase64(flipByte(raw, raw.byteLength - 1));
    await expect(decrypt(tampered, key)).rejects.toThrow();
  });

  it("fails when AAD is supplied at encrypt but missing at decrypt", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("aad-required", key, "ctx-1");
    await expect(decrypt(enc, key)).rejects.toThrow();
  });

  it("fails when AAD differs between encrypt and decrypt", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("aad-mismatch", key, "ctx-1");
    await expect(decrypt(enc, key, "ctx-2")).rejects.toThrow();
  });

  it("fails when AAD is not supplied at encrypt but provided at decrypt", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encrypt("aad-extra", key);
    await expect(decrypt(enc, key, "ctx-extra")).rejects.toThrow();
  });

  it("rejects payloads that are shorter than the IV", async () => {
    const key = await loadKey(KEY_A_BYTES);
    // 8 bytes < 12-byte IV
    const tooShort = bytesToBase64(new Uint8Array(8));
    await expect(decryptBytes(tooShort, key)).rejects.toThrow(/Invalid encrypted data/);
  });

  it("rejects ciphertexts whose base64 cannot be parsed", async () => {
    const key = await loadKey(KEY_A_BYTES);
    await expect(decrypt("!!!not-base64!!!", key)).rejects.toThrow();
  });

  it("rejects an empty ciphertext", async () => {
    const key = await loadKey(KEY_A_BYTES);
    await expect(decrypt("", key)).rejects.toThrow();
  });
});

// ============================================================================
// 4. Vault item envelopes — versioning & AAD binding
// ============================================================================

function testVaultItem(): VaultItemData {
  return {
    title: "synthetic-test-item",
    username: "user@example.test",
    password: "synthetic-password-fixture",
    notes: "synthetic notes",
    itemType: "password",
  };
}

describe("cryptoService vault item envelopes", () => {
  it("emits the current sv-vault-v1: prefix for new writes", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encryptVaultItem(testVaultItem(), key, "entry-1");

    expect(enc.startsWith(VAULT_ITEM_ENVELOPE_V1_PREFIX)).toBe(true);
    expect(isCurrentVaultItemEnvelope(enc)).toBe(true);
  });

  it("isCurrentVaultItemEnvelope returns false for legacy and empty payloads", () => {
    // Current behaviour: legacy and empty strings are classified as "not current".
    expect(isCurrentVaultItemEnvelope("legacy-base64-without-prefix")).toBe(false);
    expect(isCurrentVaultItemEnvelope("")).toBe(false);
  });

  it("isCurrentVaultItemEnvelope throws fail-closed on unknown sv-vault-* versions", () => {
    // Documented fail-closed behaviour for unknown future envelope versions:
    // we do NOT silently classify them as "not current" because that would
    // hide a future format from migration code paths. Future callers that
    // need a non-throwing predicate should add an explicit safe wrapper.
    expect(() => isCurrentVaultItemEnvelope("sv-vault-v99:future-payload")).toThrow(
      /Unsupported vault item encryption envelope version/,
    );
  });

  it("decryptVaultItem fails closed for unknown sv-vault-* versions", async () => {
    const key = await loadKey(KEY_A_BYTES);

    await expect(
      decryptVaultItem("sv-vault-v99:opaque-test-payload", key, "entry-1"),
    ).rejects.toThrow(/Unsupported vault item encryption envelope version/);
  });

  it("decryptVaultItem rejects a current envelope with the wrong entry ID (AAD mismatch)", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encryptVaultItem(testVaultItem(), key, "entry-A");

    await expect(decryptVaultItem(enc, key, "entry-B")).rejects.toThrow();
  });

  it("decryptVaultItem rejects a current envelope with an empty entry ID", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const enc = await encryptVaultItem(testVaultItem(), key, "entry-A");

    await expect(decryptVaultItem(enc, key, "")).rejects.toThrow();
  });

  it("decryptVaultItem rejects an empty current-prefix envelope payload", async () => {
    const key = await loadKey(KEY_A_BYTES);

    await expect(
      decryptVaultItem(`${VAULT_ITEM_ENVELOPE_V1_PREFIX}`, key, "entry-A"),
    ).rejects.toThrow(/Invalid vault item encryption envelope/);
  });

  it("decryptVaultItem fails closed for legacy no-AAD payloads unless the migration opt-in is set", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const json = JSON.stringify(testVaultItem());
    // Legacy payload: written without AAD AND without the v1 envelope prefix.
    const legacyCiphertext = await encrypt(json, key);

    await expect(decryptVaultItem(legacyCiphertext, key, "entry-A")).rejects.toThrow(
      /Legacy vault item without AAD requires migration/,
    );
  });
});

// ============================================================================
// 5. Shared-key (collection) envelopes
// ============================================================================

describe("cryptoService shared-key contract", () => {
  it("encryptWithSharedKey/decryptWithSharedKey round-trip with matching AAD", async () => {
    const sharedKey = await generateSharedKey();
    const item = { ...testVaultItem(), title: "shared-roundtrip" };

    const enc = await encryptWithSharedKey(item, sharedKey, "shared-entry-1");
    await expect(decryptWithSharedKey(enc, sharedKey, "shared-entry-1")).resolves.toMatchObject({
      title: "shared-roundtrip",
    });
  });

  it("decryptWithSharedKey fails closed on AAD swap by default", async () => {
    const sharedKey = await generateSharedKey();
    const enc = await encryptWithSharedKey(testVaultItem(), sharedKey, "shared-entry-A");

    await expect(decryptWithSharedKey(enc, sharedKey, "shared-entry-B")).rejects.toThrow(
      /Shared item decryption failed with the required AAD context/,
    );
  });

  it("decryptWithSharedKey only allows legacy no-AAD reads when the explicit migration option is set", async () => {
    const sharedKey = await generateSharedKey();

    // Build a legacy (no-AAD) ciphertext using the public encrypt() helper
    // and the decoded shared AES key (as JWK -> CryptoKey).
    const keyJwk = JSON.parse(sharedKey) as JsonWebKey;
    const aesKey = await crypto.subtle.importKey(
      "jwk",
      keyJwk,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const legacyCiphertext = await encrypt(JSON.stringify(testVaultItem()), aesKey);

    // Without the opt-in, even a legacy ciphertext with the right key is
    // rejected once we are in the AAD-required code path.
    await expect(
      decryptWithSharedKey(legacyCiphertext, sharedKey, "shared-entry-X"),
    ).rejects.toThrow(/Shared item decryption failed with the required AAD context/);

    await expect(
      decryptWithSharedKey(legacyCiphertext, sharedKey, "shared-entry-X", {
        allowLegacyNoAadFallback: true,
      }),
    ).resolves.toMatchObject({ title: "synthetic-test-item" });
  });

  it("generateSharedKey produces an AES-GCM 256 JWK", async () => {
    const sharedKey = await generateSharedKey();
    const jwk = JSON.parse(sharedKey) as JsonWebKey;
    expect(jwk.kty).toBe("oct");
    expect(jwk.alg).toBe("A256GCM");
    // The exported raw key has 32 bytes → base64url length 43 (no padding).
    expect(typeof jwk.k).toBe("string");
  });
});

// ============================================================================
// 6. Verification hash contract
// ============================================================================

describe("cryptoService verification hash", () => {
  it("createVerificationHash + verifyKey accepts the matching key and rejects others", async () => {
    const keyA = await loadKey(KEY_A_BYTES);
    const keyB = await loadKey(KEY_B_BYTES);

    const verifier = await createVerificationHash(keyA);

    expect(verifier.startsWith("v3:")).toBe(true);
    await expect(verifyKey(verifier, keyA)).resolves.toBe(true);
    await expect(verifyKey(verifier, keyB)).resolves.toBe(false);
  });

  it("verifyKey returns false for a malformed verifier (no throw)", async () => {
    const key = await loadKey(KEY_A_BYTES);
    await expect(verifyKey("v3:not-a-real-ciphertext", key)).resolves.toBe(false);
    await expect(verifyKey("not-a-known-format", key)).resolves.toBe(false);
  });
});

// ============================================================================
// 7. KDF parameter stability
// ============================================================================

describe("cryptoService KDF parameter stability", () => {
  it("CURRENT_KDF_VERSION is a positive integer with a defined parameter set", () => {
    expect(Number.isInteger(CURRENT_KDF_VERSION)).toBe(true);
    expect(CURRENT_KDF_VERSION).toBeGreaterThan(0);
    expect(KDF_PARAMS[CURRENT_KDF_VERSION]).toBeDefined();
  });

  it("KDF_PARAMS v1 is byte-stable (frozen for backward compat)", () => {
    expect(KDF_PARAMS[1]).toEqual({
      memory: 65536,
      iterations: 3,
      parallelism: 4,
      hashLength: 32,
    });
  });

  it("KDF_PARAMS v2 is byte-stable (frozen for backward compat)", () => {
    expect(KDF_PARAMS[2]).toEqual({
      memory: 131072,
      iterations: 3,
      parallelism: 4,
      hashLength: 32,
    });
  });

  it("every released KDF version asks for AES-256-sized output (32 bytes)", () => {
    for (const version of Object.keys(KDF_PARAMS)) {
      expect(KDF_PARAMS[Number(version)].hashLength).toBe(32);
    }
  });

  it("generateSalt() returns a 16-byte (Base64) value", () => {
    const salt = generateSalt();
    const raw = base64ToBytes(salt);
    expect(raw.byteLength).toBe(16);
  });
});

// ============================================================================
// 8. UserKey wrapping contract
// ============================================================================

describe("cryptoService UserKey wrapping", () => {
  it("createEncryptedUserKey produces an unwrappable bundle and a usable UserKey", async () => {
    // 32 random bytes — synthetic stand-in for Argon2id output.
    const kdfOutput = crypto.getRandomValues(new Uint8Array(32));

    const { encryptedUserKey, userKey } = await createEncryptedUserKey(kdfOutput);
    expect(encryptedUserKey.startsWith("usk-wrap-v2:")).toBe(true);

    // The returned userKey must round-trip through the public encrypt API.
    const enc = await encrypt("user-key-roundtrip", userKey);
    await expect(decrypt(enc, userKey)).resolves.toBe("user-key-roundtrip");

    // Re-deriving the same UserKey from the encrypted bundle yields a key
    // that decrypts the same ciphertext.
    const recovered = await unwrapUserKey(encryptedUserKey, kdfOutput);
    await expect(decrypt(enc, recovered)).resolves.toBe("user-key-roundtrip");
  });

  it("unwrapUserKey fails for the wrong KDF output", async () => {
    const kdfOutputA = crypto.getRandomValues(new Uint8Array(32));
    const kdfOutputB = crypto.getRandomValues(new Uint8Array(32));

    const { encryptedUserKey } = await createEncryptedUserKey(kdfOutputA);
    await expect(unwrapUserKey(encryptedUserKey, kdfOutputB)).rejects.toThrow();
  });

  it("unwrapUserKeyBytes returns 32 secret bytes for a fresh bundle", async () => {
    const kdfOutput = crypto.getRandomValues(new Uint8Array(32));
    const { encryptedUserKey } = await createEncryptedUserKey(kdfOutput);

    const bytes = await unwrapUserKeyBytes(encryptedUserKey, kdfOutput);
    expect(bytes.byteLength).toBe(32);
  });

  it("rewrapUserKey switches the wrap-key without changing the underlying UserKey", async () => {
    const oldKdfOutput = crypto.getRandomValues(new Uint8Array(32));
    const newKdfOutput = crypto.getRandomValues(new Uint8Array(32));

    const { encryptedUserKey: oldWrap, userKey } = await createEncryptedUserKey(oldKdfOutput);
    const enc = await encrypt("rewrap-fixture", userKey);

    const newWrap = await rewrapUserKey(oldWrap, oldKdfOutput, newKdfOutput);
    expect(newWrap).not.toBe(oldWrap);
    expect(newWrap.startsWith("usk-wrap-v2:")).toBe(true);

    const recovered = await unwrapUserKey(newWrap, newKdfOutput);
    await expect(decrypt(enc, recovered)).resolves.toBe("rewrap-fixture");

    // The old KDF output must no longer unwrap the rotated bundle.
    await expect(unwrapUserKey(newWrap, oldKdfOutput)).rejects.toThrow();
  });
});

// ============================================================================
// 9. Private key wrapping with the UserKey
// ============================================================================

describe("cryptoService private-key wrapping", () => {
  it("wrapPrivateKeyWithUserKey + unwrap round-trip preserves the JWK string", async () => {
    const kdfOutput = crypto.getRandomValues(new Uint8Array(32));
    const { userKey } = await createEncryptedUserKey(kdfOutput);
    // Synthetic JWK-shaped string — never a real key.
    const fakePrivateKey = JSON.stringify({ kty: "RSA", n: "AA", e: "AQAB" });

    const wrapped = await wrapPrivateKeyWithUserKey(fakePrivateKey, userKey);
    expect(wrapped.startsWith("usk-v1:")).toBe(true);

    const unwrapped = await unwrapPrivateKeyWithUserKey(wrapped, userKey);
    expect(unwrapped).toBe(fakePrivateKey);
  });

  it("unwrapPrivateKeyWithUserKey fails closed when the prefix is missing", async () => {
    const kdfOutput = crypto.getRandomValues(new Uint8Array(32));
    const { userKey } = await createEncryptedUserKey(kdfOutput);

    await expect(unwrapPrivateKeyWithUserKey("no-prefix", userKey)).rejects.toThrow(
      /missing usk-v1: prefix/,
    );
  });

  it("unwrapPrivateKeyWithUserKey fails when wrapped under a different UserKey", async () => {
    const kdfOutputA = crypto.getRandomValues(new Uint8Array(32));
    const kdfOutputB = crypto.getRandomValues(new Uint8Array(32));
    const { userKey: ukA } = await createEncryptedUserKey(kdfOutputA);
    const { userKey: ukB } = await createEncryptedUserKey(kdfOutputB);

    const wrapped = await wrapPrivateKeyWithUserKey("synthetic-private-key", ukA);
    await expect(unwrapPrivateKeyWithUserKey(wrapped, ukB)).rejects.toThrow();
  });
});

// ============================================================================
// 10. Secret/log-safety guard rails on error messages
// ============================================================================

describe("cryptoService error-message hygiene", () => {
  it("does not leak the plaintext into the error of a wrong-key decrypt", async () => {
    const keyA = await loadKey(KEY_A_BYTES);
    const keyB = await loadKey(KEY_B_BYTES);
    const marker = "EXTRA_SECRET_MARKER_DO_NOT_LEAK";
    const enc = await encrypt(marker, keyA);

    let captured: unknown;
    try {
      await decrypt(enc, keyB);
    } catch (err) {
      captured = err;
    }

    expect(captured).toBeDefined();
    const message = (captured as Error)?.message ?? String(captured);
    expect(message).not.toContain(marker);
    expect(message).not.toContain(enc);
  });

  it("does not leak the AAD into the error of a tampered-AAD decrypt", async () => {
    const key = await loadKey(KEY_A_BYTES);
    const aad = "ctx-secret-marker-AAD";
    const enc = await encrypt("some-text", key, aad);

    let captured: unknown;
    try {
      await decrypt(enc, key, "ctx-different");
    } catch (err) {
      captured = err;
    }

    expect(captured).toBeDefined();
    const message = (captured as Error)?.message ?? String(captured);
    expect(message).not.toContain(aad);
  });
});
