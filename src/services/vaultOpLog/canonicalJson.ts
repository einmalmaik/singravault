// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `canonicalizeVaultStructure` produces a deterministic UTF-8 byte
 * encoding for every signed or hashed vault structure.
 *
 * Rules (binding, see ADR-0004 §19.2 and concept §19.2):
 *
 *  - `undefined`, `NaN`, `+Infinity`, `-Infinity`, `Symbol`,
 *    `Function`, `BigInt` are rejected anywhere in the tree.
 *  - `null` is preserved and is not equivalent to a missing key.
 *  - Strings are Unicode NFC normalised (both values and keys).
 *  - Object keys are sorted by their UTF-8 byte sequence, not by
 *    locale.
 *  - Numbers are emitted as JSON integers when they are safe
 *    integers; otherwise as shortest-round-trip finite decimal form.
 *  - Arrays preserve their input order.
 *  - The output is a `Uint8Array` of UTF-8 bytes, not a JS string.
 *  - Cyclic structures are rejected.
 *
 * `JSON.stringify` is intentionally not used on the canonical path:
 * it drops `undefined`, it does not normalise strings, it orders
 * keys by insertion, it does not reject `BigInt`, and its "key
 * ordering" is engine-defined for string-indexed property iteration
 * and therefore not safe for byte-stable signatures.
 */

import {
  VaultCanonicalizationError,
  VaultCryptoError,
  type VaultCanonicalizationErrorCode,
} from './types';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Produce canonical UTF-8 bytes for a JSON-compatible value. The
 * value must be composed of plain objects, arrays, strings, safe
 * numbers, booleans or `null`.
 */
export function canonicalizeVaultStructure(value: unknown): Uint8Array {
  const parts: string[] = [];
  const seen = new WeakSet<object>();
  emit(value, parts, seen, []);
  return textEncoder.encode(parts.join(''));
}

/**
 * Convenience: produce canonical UTF-8 bytes and decode them as a
 * string. Intended for tests and for debug-only diagnostics. Never
 * feed the string back into a hash / signature; feed the bytes.
 */
export function canonicalizeVaultStructureAsString(value: unknown): string {
  return textDecoder.decode(canonicalizeVaultStructure(value));
}

function emit(
  value: unknown,
  parts: string[],
  seen: WeakSet<object>,
  path: Array<string | number>,
): void {
  if (value === null) {
    parts.push('null');
    return;
  }

  const valueType = typeof value;

  if (valueType === 'undefined') {
    throw makeError('undefined_not_allowed', path);
  }
  if (valueType === 'symbol') {
    throw makeError('symbol_not_allowed', path);
  }
  if (valueType === 'function') {
    throw makeError('function_not_allowed', path);
  }
  if (valueType === 'bigint') {
    throw makeError('bigint_not_allowed', path);
  }

  if (valueType === 'boolean') {
    parts.push(value ? 'true' : 'false');
    return;
  }

  if (valueType === 'number') {
    emitNumber(value as number, parts, path);
    return;
  }

  if (valueType === 'string') {
    emitString(value as string, parts);
    return;
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      throw makeError('cyclic_reference', path);
    }
    seen.add(value);
    parts.push('[');
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) {
        parts.push(',');
      }
      emit(value[index], parts, seen, [...path, index]);
    }
    parts.push(']');
    seen.delete(value);
    return;
  }

  if (valueType === 'object') {
    if (!isPlainObject(value)) {
      throw makeError('unsupported_value', path);
    }
    const obj = value as Record<string, unknown>;
    if (seen.has(obj)) {
      throw makeError('cyclic_reference', path);
    }
    seen.add(obj);
    const entries = sortEntriesByUtf8(obj, path);
    parts.push('{');
    for (let index = 0; index < entries.length; index += 1) {
      if (index > 0) {
        parts.push(',');
      }
      const [normalisedKey, entryValue] = entries[index];
      emitString(normalisedKey, parts);
      parts.push(':');
      emit(entryValue, parts, seen, [...path, normalisedKey]);
    }
    parts.push('}');
    seen.delete(obj);
    return;
  }

  throw makeError('unsupported_value', path);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sortEntriesByUtf8(
  obj: Record<string, unknown>,
  path: Array<string | number>,
): Array<[string, unknown]> {
  const keys = Object.keys(obj);
  const prepared: Array<{ normalisedKey: string; bytes: Uint8Array; value: unknown }> = [];
  for (let index = 0; index < keys.length; index += 1) {
    const rawKey = keys[index];
    const normalisedKey = rawKey.normalize('NFC');
    prepared.push({
      normalisedKey,
      bytes: textEncoder.encode(normalisedKey),
      value: obj[rawKey],
    });
  }
  // Detect collisions that happen when two different input keys
  // NFC-normalise to the same string. Signed inputs must never carry
  // ambiguity like that.
  for (let outer = 0; outer < prepared.length; outer += 1) {
    for (let inner = outer + 1; inner < prepared.length; inner += 1) {
      if (prepared[outer].normalisedKey === prepared[inner].normalisedKey) {
        throw new VaultCanonicalizationError('unsupported_value', [...path, prepared[outer].normalisedKey]);
      }
    }
  }
  prepared.sort((left, right) => compareUtf8Bytes(left.bytes, right.bytes));
  return prepared.map((entry) => [entry.normalisedKey, entry.value]);
}

function compareUtf8Bytes(a: Uint8Array, b: Uint8Array): number {
  const min = a.length < b.length ? a.length : b.length;
  for (let index = 0; index < min; index += 1) {
    if (a[index] !== b[index]) {
      return a[index] - b[index];
    }
  }
  return a.length - b.length;
}

function emitNumber(value: number, parts: string[], path: Array<string | number>): void {
  if (!Number.isFinite(value)) {
    throw makeError('non_finite_number', path);
  }
  if (Number.isNaN(value)) {
    throw makeError('non_finite_number', path);
  }
  // Pin integer formatting so `1.0` never sneaks in as a float.
  if (Number.isInteger(value) && Number.isSafeInteger(value)) {
    parts.push(value.toString(10));
    return;
  }
  // Shortest-round-trip decimal form. `Number.prototype.toString` is
  // already shortest-round-trip per ECMA-262. Avoid exponential form
  // when a plain decimal form is shorter and unambiguous so two
  // clients always emit the same bytes for the same double.
  const plain = value.toString(10);
  parts.push(plain);
}

function emitString(value: string, parts: string[]): void {
  const normalised = value.normalize('NFC');
  parts.push('"');
  for (let index = 0; index < normalised.length; index += 1) {
    const code = normalised.charCodeAt(index);
    const char = normalised[index];
    if (char === '"') {
      parts.push('\\"');
    } else if (char === '\\') {
      parts.push('\\\\');
    } else if (code === 0x08) {
      parts.push('\\b');
    } else if (code === 0x09) {
      parts.push('\\t');
    } else if (code === 0x0a) {
      parts.push('\\n');
    } else if (code === 0x0c) {
      parts.push('\\f');
    } else if (code === 0x0d) {
      parts.push('\\r');
    } else if (code < 0x20) {
      parts.push('\\u');
      parts.push(code.toString(16).padStart(4, '0'));
    } else {
      parts.push(char);
    }
  }
  parts.push('"');
}

function makeError(
  code: VaultCanonicalizationErrorCode,
  path: Array<string | number>,
): VaultCanonicalizationError {
  return new VaultCanonicalizationError(code, [...path]);
}

// ---------------------------------------------------------------
// Base64url helpers (RFC 4648 §5, no padding).
// ---------------------------------------------------------------

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Encode raw bytes as base64url without padding.
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  let output = '';
  const length = bytes.length;
  for (let index = 0; index < length; index += 3) {
    const byte0 = bytes[index];
    const byte1 = index + 1 < length ? bytes[index + 1] : undefined;
    const byte2 = index + 2 < length ? bytes[index + 2] : undefined;

    output += BASE64URL_ALPHABET[byte0 >> 2];
    if (byte1 === undefined) {
      output += BASE64URL_ALPHABET[(byte0 & 0x03) << 4];
      break;
    }
    output += BASE64URL_ALPHABET[((byte0 & 0x03) << 4) | (byte1 >> 4)];
    if (byte2 === undefined) {
      output += BASE64URL_ALPHABET[(byte1 & 0x0f) << 2];
      break;
    }
    output += BASE64URL_ALPHABET[((byte1 & 0x0f) << 2) | (byte2 >> 6)];
    output += BASE64URL_ALPHABET[byte2 & 0x3f];
  }
  return output;
}

const BASE64URL_LOOKUP = new Int8Array(128).fill(-1);
for (let index = 0; index < BASE64URL_ALPHABET.length; index += 1) {
  BASE64URL_LOOKUP[BASE64URL_ALPHABET.charCodeAt(index)] = index;
}

/**
 * Decode a base64url string (without padding, or with any trailing
 * `=` stripped) into raw bytes. Throws `VaultCryptoError` with code
 * `base64url_invalid` on malformed input.
 */
export function decodeBase64Url(input: string): Uint8Array {
  const trimmed = input.endsWith('=') ? input.replace(/=+$/u, '') : input;
  const length = trimmed.length;
  if (length === 0) {
    return new Uint8Array(0);
  }
  const remainder = length % 4;
  if (remainder === 1) {
    throw new VaultCryptoError('base64url_invalid', 'base64url length invalid');
  }
  const byteLength = Math.floor((length * 3) / 4);
  const output = new Uint8Array(byteLength);
  let outIndex = 0;
  for (let index = 0; index < length; index += 4) {
    const c0 = lookupBase64Url(trimmed.charCodeAt(index));
    const c1 = lookupBase64Url(trimmed.charCodeAt(index + 1));
    const c2 = index + 2 < length ? lookupBase64Url(trimmed.charCodeAt(index + 2)) : -1;
    const c3 = index + 3 < length ? lookupBase64Url(trimmed.charCodeAt(index + 3)) : -1;
    output[outIndex] = (c0 << 2) | (c1 >> 4);
    outIndex += 1;
    if (c2 !== -1) {
      output[outIndex] = ((c1 & 0x0f) << 4) | (c2 >> 2);
      outIndex += 1;
    }
    if (c3 !== -1) {
      output[outIndex] = ((c2 & 0x03) << 6) | c3;
      outIndex += 1;
    }
  }
  return output.subarray(0, outIndex);
}

function lookupBase64Url(code: number): number {
  if (code < 0 || code >= BASE64URL_LOOKUP.length) {
    throw new VaultCryptoError('base64url_invalid', 'base64url char out of range');
  }
  const value = BASE64URL_LOOKUP[code];
  if (value < 0) {
    throw new VaultCryptoError('base64url_invalid', 'base64url char not in alphabet');
  }
  return value;
}

/**
 * Cross-realm-safe check for `Uint8Array`. `instanceof` breaks when
 * a value is produced by a different JS realm (e.g. a jsdom window
 * whose `Uint8Array` is not the same identity as the module-level
 * one). We accept any value that stringifies as `[object Uint8Array]`
 * which is what `Uint8Array.prototype[Symbol.toStringTag]` produces.
 */
export function isUint8ArrayLike(value: unknown): value is Uint8Array {
  if (value == null || typeof value !== 'object') {
    return false;
  }
  return Object.prototype.toString.call(value) === '[object Uint8Array]';
}

/**
 * Constant-time byte array equality. Both inputs must already have
 * the same length; the function still runs in data-independent time
 * across the overlap.
 */
export function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a[index] ^ b[index];
  }
  return diff === 0;
}
