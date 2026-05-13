// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * JSONB roundtrip test vectors for canonicalize idempotency.
 *
 * These tests verify that canonicalizeVaultStructure produces idempotent
 * byte output when roundtripped through JSONB (PostgreSQL's binary JSON format).
 * This is critical for ensuring that signatures and hashes remain stable
 * when data is stored in and retrieved from the database.
 *
 * Idempotency property:
 *   canonicalize(parse(JSON.stringify(canonicalize(obj)))) === canonicalize(obj)
 *
 * In practice, this means:
 * 1. Canonicalize an object to bytes
 * 2. Parse as UTF-8 to get JSON string
 * 3. Parse JSON string back to object
 * 4. Canonicalize again
 * 5. Resulting bytes must be identical
 */

import { describe, it, expect } from 'vitest';
import { canonicalizeVaultStructure } from '../canonicalJson';

describe('JSONB roundtrip — canonicalize idempotency', () => {
  it('is idempotent for simple objects', () => {
    const obj = { a: 1, b: 2 };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    // Simulate JSONB roundtrip: bytes -> string -> parse -> canonicalize
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for nested objects', () => {
    const obj = { a: { b: { c: 1 } }, d: 2 };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for arrays', () => {
    const obj = { arr: [1, 2, 3] };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for mixed structures', () => {
    const obj = {
      string: 'test',
      number: 42,
      boolean: true,
      null: null,
      array: [1, 2, 3],
      nested: { a: 1, b: 2 },
    };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for VaultOperationSignedBodyV1 shape', () => {
    const obj = {
      signatureSchema: 'device-signature-v1',
      opId: 'op-123',
      vaultId: 'vault-456',
      authorDeviceId: 'device-789',
      opType: 'create',
      recordId: 'record-abc',
      recordType: 'item',
      baseRecordVersion: null,
      previousCiphertextHash: null,
      newRecordHash: 'hash-def',
      baseVaultHead: null,
      payloadCiphertextHash: 'ct-ghi',
      payloadAadHash: 'aad-jkl',
      createdAtClient: '2026-05-02T10:00:00.000Z',
      trustEpoch: 0,
      intentId: 'intent-mno',
      rebasedFromOpId: null,
    };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for RecordAadV1 shape', () => {
    const obj = {
      app: 'singra-vault',
      aadSchema: 'record-aad-v1',
      vaultId: 'vault-123',
      recordId: 'record-456',
      recordType: 'item',
      recordVersion: 1,
      keyVersion: 1,
      encryptionSchema: 'record-aead-v1',
    };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('preserves null values through roundtrip', () => {
    const obj = { a: 1, b: null, c: 2 };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
    // Verify null is preserved, not dropped
    expect(parsed.b).toBeNull();
  });

  it('preserves key ordering through roundtrip', () => {
    // Keys are sorted by UTF-8 bytes in canonicalize
    const obj = { z: 1, a: 2, m: 3 };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
    // Keys should be sorted: a, m, z
    const keys = Object.keys(parsed);
    expect(keys).toEqual(['a', 'm', 'z']);
  });

  it('is idempotent for Unicode strings', () => {
    const obj = { str: 'Hello 世界 ß ä' };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    const jsonStr = new TextDecoder().decode(bytes1);
    const parsed = JSON.parse(jsonStr);
    const bytes2 = canonicalizeVaultStructure(parsed);
    
    expect(bytes2).toEqual(bytes1);
  });

  it('is idempotent for empty objects and arrays', () => {
    const obj1 = {};
    const bytes1 = canonicalizeVaultStructure(obj1);
    
    const jsonStr1 = new TextDecoder().decode(bytes1);
    const parsed1 = JSON.parse(jsonStr1);
    const bytes2 = canonicalizeVaultStructure(parsed1);
    
    expect(bytes2).toEqual(bytes1);

    const obj2 = { arr: [] };
    const bytes3 = canonicalizeVaultStructure(obj2);
    
    const jsonStr2 = new TextDecoder().decode(bytes3);
    const parsed2 = JSON.parse(jsonStr2);
    const bytes4 = canonicalizeVaultStructure(parsed2);
    
    expect(bytes4).toEqual(bytes3);
  });

  it('handles double roundtrip (canonicalize -> JSONB -> canonicalize -> JSONB -> canonicalize)', () => {
    const obj = { a: 1, b: { c: [2, 3] }, d: null };
    const bytes1 = canonicalizeVaultStructure(obj);
    
    // First roundtrip
    const jsonStr1 = new TextDecoder().decode(bytes1);
    const parsed1 = JSON.parse(jsonStr1);
    const bytes2 = canonicalizeVaultStructure(parsed1);
    
    // Second roundtrip
    const jsonStr2 = new TextDecoder().decode(bytes2);
    const parsed2 = JSON.parse(jsonStr2);
    const bytes3 = canonicalizeVaultStructure(parsed2);
    
    // All three should be identical
    expect(bytes2).toEqual(bytes1);
    expect(bytes3).toEqual(bytes1);
  });
});
