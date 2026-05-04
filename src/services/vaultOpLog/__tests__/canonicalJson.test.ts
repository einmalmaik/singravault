// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  canonicalizeVaultStructure,
  canonicalizeVaultStructureAsString,
  constantTimeEquals,
  decodeBase64Url,
  encodeBase64Url,
} from '../canonicalJson';
import { VaultCanonicalizationError, VaultCryptoError } from '../types';

const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();

describe('canonicalizeVaultStructure — byte vectors', () => {
  it('emits an empty object as the 2-byte literal {}', () => {
    const bytes = canonicalizeVaultStructure({});
    expect(decoder.decode(bytes)).toBe('{}');
    expect(bytes.length).toBe(2);
  });

  it('emits an empty array as the 2-byte literal []', () => {
    const bytes = canonicalizeVaultStructure([]);
    expect(decoder.decode(bytes)).toBe('[]');
  });

  it('sorts keys by UTF-8 byte sequence, not locale', () => {
    // UTF-8 bytes: 'a' (0x61), 'z' (0x7A), 'ß' (0xC3 0x9F), 'ä' (0xC3 0xA4).
    // Because the first byte of both 'ß' and 'ä' is 0xC3, the second byte
    // decides: 0x9F < 0xA4, so 'ß' comes before 'ä'.
    const bytes = canonicalizeVaultStructure({ z: 1, a: 2, 'ß': 3, 'ä': 4 });
    expect(decoder.decode(bytes)).toBe('{"a":2,"z":1,"ß":3,"ä":4}');
  });

  it('NFC-normalises keys and values', () => {
    // Composed 'é' (U+00E9) and decomposed 'e' + COMBINING ACUTE ACCENT.
    // Canonicalisation must produce the NFC form for both.
    const composed = '\u00E9';
    const decomposed = 'e\u0301';
    const bytesA = canonicalizeVaultStructure({ name: composed });
    const bytesB = canonicalizeVaultStructure({ name: decomposed });
    expect(decoder.decode(bytesA)).toBe(decoder.decode(bytesB));
    expect(decoder.decode(bytesA)).toBe('{"name":"\u00E9"}');
  });

  it('rejects two input keys that NFC-normalise to the same string', () => {
    const input: Record<string, unknown> = {};
    input['\u00E9'] = 1;
    input['e\u0301'] = 2;
    expect(() => canonicalizeVaultStructure(input)).toThrow(VaultCanonicalizationError);
  });

  it('preserves null explicitly', () => {
    const bytes = canonicalizeVaultStructure({ previousHash: null, version: 1 });
    expect(decoder.decode(bytes)).toBe('{"previousHash":null,"version":1}');
  });

  it('rejects undefined anywhere in the structure', () => {
    expect(() => canonicalizeVaultStructure({ a: undefined })).toThrow(VaultCanonicalizationError);
    expect(() => canonicalizeVaultStructure([1, undefined, 3])).toThrow(VaultCanonicalizationError);
  });

  it('rejects NaN and infinities', () => {
    expect(() => canonicalizeVaultStructure({ x: NaN })).toThrow(VaultCanonicalizationError);
    expect(() => canonicalizeVaultStructure({ x: Infinity })).toThrow(VaultCanonicalizationError);
    expect(() => canonicalizeVaultStructure({ x: -Infinity })).toThrow(VaultCanonicalizationError);
  });

  it('rejects BigInt, Symbol, and functions', () => {
    expect(() => canonicalizeVaultStructure({ x: 1n })).toThrow(VaultCanonicalizationError);
    expect(() => canonicalizeVaultStructure({ x: Symbol('x') })).toThrow(VaultCanonicalizationError);
    expect(() => canonicalizeVaultStructure({ x: () => 0 })).toThrow(VaultCanonicalizationError);
  });

  it('rejects non-plain objects (e.g. class instances)', () => {
    class Custom {
      public readonly x = 1;
    }
    expect(() => canonicalizeVaultStructure(new Custom())).toThrow(VaultCanonicalizationError);
  });

  it('rejects cyclic references', () => {
    const a: Record<string, unknown> = {};
    a.self = a;
    expect(() => canonicalizeVaultStructure(a)).toThrow(VaultCanonicalizationError);
  });

  it('emits safe integers as integers and control characters as \\u escapes', () => {
    const bytes = canonicalizeVaultStructure({
      count: 42,
      ctrl: '\u0001',
      newline: 'a\nb',
    });
    expect(decoder.decode(bytes)).toBe('{"count":42,"ctrl":"\\u0001","newline":"a\\nb"}');
  });

  it('returns UTF-8 bytes, not a JS string', () => {
    const bytes = canonicalizeVaultStructure({ text: '€' });
    // € is 3 bytes in UTF-8 (0xE2 0x82 0xAC)
    expect(Object.prototype.toString.call(bytes)).toBe('[object Uint8Array]');
    const expected = encoder.encode('{"text":"€"}');
    expect(bytes.length).toBe(expected.length);
    for (let i = 0; i < expected.length; i += 1) {
      expect(bytes[i]).toBe(expected[i]);
    }
  });

  it('is deterministic: same input produces exactly the same bytes', () => {
    const payload = {
      b: [1, 2, 3],
      a: { nested: { y: 'b', x: 'a' }, flag: true },
    };
    const first = canonicalizeVaultStructure(payload);
    const second = canonicalizeVaultStructure({ ...payload });
    expect(constantTimeEquals(first, second)).toBe(true);
  });

  it('is sensitive: one-byte change in input produces a different output', () => {
    const original = canonicalizeVaultStructure({ field: 'value' });
    const mutated = canonicalizeVaultStructure({ field: 'valuf' });
    expect(constantTimeEquals(original, mutated)).toBe(false);
  });

  it('exposes a debug-only string form that equals the byte decoding', () => {
    const payload = { a: 1, b: 'x' };
    expect(canonicalizeVaultStructureAsString(payload)).toBe(decoder.decode(canonicalizeVaultStructure(payload)));
  });
});

describe('base64url', () => {
  it('encodes and decodes round-trip', () => {
    const bytes = new Uint8Array([0, 1, 2, 3, 4, 250, 251, 252, 253, 254, 255]);
    const encoded = encodeBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/u);
    const decoded = decodeBase64Url(encoded);
    expect(constantTimeEquals(decoded, bytes)).toBe(true);
  });

  it('encodes the empty byte array as the empty string', () => {
    expect(encodeBase64Url(new Uint8Array(0))).toBe('');
    expect(decodeBase64Url('').length).toBe(0);
  });

  it('uses URL-safe alphabet (- and _, not + and /)', () => {
    // 0xfb 0xef 0xff in binary groups of 6: 111110 111110 111111 111111 =
    // indices 62 62 63 63 → '-' '-' '_' '_'. Both replacement characters
    // appear, proving the encoder is URL-safe rather than standard.
    const bytes = new Uint8Array([0xfb, 0xef, 0xff]);
    const encoded = encodeBase64Url(bytes);
    expect(encoded).toBe('--__');
    expect(encoded).not.toMatch(/[+/]/u);
    expect(constantTimeEquals(decodeBase64Url(encoded), bytes)).toBe(true);
  });

  it('rejects malformed base64url inputs', () => {
    expect(() => decodeBase64Url('!!')).toThrow(VaultCryptoError);
    expect(() => decodeBase64Url('a')).toThrow(VaultCryptoError);
  });
});

describe('constantTimeEquals', () => {
  it('returns true only for identical byte sequences', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    expect(constantTimeEquals(a, b)).toBe(true);
    expect(constantTimeEquals(a, c)).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(constantTimeEquals(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
});
