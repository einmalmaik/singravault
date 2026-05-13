// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  APP_NAMESPACE,
  RECORD_AAD_SCHEMA_V1,
  RECORD_ENCRYPTION_SCHEMA_V1,
  VaultCryptoError,
} from '../types';
import {
  buildRecordAad,
  encodeRecordAadBytes,
  recordAadsEqual,
} from '../recordAad';

const decoder = new TextDecoder('utf-8', { fatal: true });

describe('buildRecordAad', () => {
  it('pins the protocol schema fields regardless of the inputs', () => {
    const aad = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 0,
      keyVersion: 1,
    });
    expect(aad.app).toBe(APP_NAMESPACE);
    expect(aad.aadSchema).toBe(RECORD_AAD_SCHEMA_V1);
    expect(aad.encryptionSchema).toBe(RECORD_ENCRYPTION_SCHEMA_V1);
  });

  it('accepts every defined record type', () => {
    const types = [
      'item',
      'category',
      'attachment_metadata',
      'attachment_chunk',
      'manifest',
      'tombstone',
    ] as const;
    for (const recordType of types) {
      expect(
        buildRecordAad({
          vaultId: 'v1',
          recordId: 'r1',
          recordType,
          recordVersion: 0,
          keyVersion: 0,
        }).recordType,
      ).toBe(recordType);
    }
  });

  it('rejects unknown record types', () => {
    expect(() =>
      buildRecordAad({
        vaultId: 'v1',
        recordId: 'r1',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        recordType: 'not-a-record-type' as any,
        recordVersion: 0,
        keyVersion: 0,
      }),
    ).toThrow(VaultCryptoError);
  });

  it('rejects negative or non-integer versions', () => {
    const base = {
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item' as const,
      recordVersion: 0,
      keyVersion: 0,
    };
    expect(() => buildRecordAad({ ...base, recordVersion: -1 })).toThrow(VaultCryptoError);
    expect(() => buildRecordAad({ ...base, recordVersion: 1.5 })).toThrow(VaultCryptoError);
    expect(() => buildRecordAad({ ...base, keyVersion: -1 })).toThrow(VaultCryptoError);
    expect(() => buildRecordAad({ ...base, keyVersion: 1.5 })).toThrow(VaultCryptoError);
  });

  it('rejects empty vaultId or recordId', () => {
    expect(() =>
      buildRecordAad({
        vaultId: '',
        recordId: 'r1',
        recordType: 'item',
        recordVersion: 0,
        keyVersion: 0,
      }),
    ).toThrow(VaultCryptoError);
    expect(() =>
      buildRecordAad({
        vaultId: 'v1',
        recordId: '',
        recordType: 'item',
        recordVersion: 0,
        keyVersion: 0,
      }),
    ).toThrow(VaultCryptoError);
  });
});

describe('encodeRecordAadBytes', () => {
  it('produces a byte-stable canonical form with keys sorted by UTF-8', () => {
    const aad = buildRecordAad({
      vaultId: 'vault-1',
      recordId: 'rec-1',
      recordType: 'item',
      recordVersion: 3,
      keyVersion: 1,
    });
    const text = decoder.decode(encodeRecordAadBytes(aad));
    // Keys sorted by UTF-8 bytes: aadSchema < app < encryptionSchema <
    // keyVersion < recordId < recordType < recordVersion < vaultId.
    expect(text).toBe(
      '{"aadSchema":"record-aad-v1","app":"singra-vault","encryptionSchema":"record-aead-v1",'
      + '"keyVersion":1,"recordId":"rec-1","recordType":"item","recordVersion":3,"vaultId":"vault-1"}',
    );
  });

  it('is sensitive to recordVersion', () => {
    const a = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 1,
      keyVersion: 1,
    });
    const b = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 2,
      keyVersion: 1,
    });
    expect(recordAadsEqual(a, b)).toBe(false);
  });

  it('is sensitive to recordType', () => {
    const a = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 1,
      keyVersion: 1,
    });
    const b = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'category',
      recordVersion: 1,
      keyVersion: 1,
    });
    expect(recordAadsEqual(a, b)).toBe(false);
  });

  it('equal inputs produce byte-equal AAD', () => {
    const a = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 1,
      keyVersion: 1,
    });
    const b = buildRecordAad({
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      recordVersion: 1,
      keyVersion: 1,
    });
    expect(recordAadsEqual(a, b)).toBe(true);
  });
});
