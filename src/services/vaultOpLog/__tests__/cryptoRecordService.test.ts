// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  deriveRecordKey,
  openRecord,
  sealRecord,
} from '../cryptoRecordService';
import { buildRecordAad } from '../recordAad';
import { VaultCryptoError, type BuildRecordAadInput } from '../types';
import { constantTimeEquals, decodeBase64Url } from '../canonicalJson';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function randomVaultKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function sampleAadInput(overrides: Partial<BuildRecordAadInput> = {}): BuildRecordAadInput {
  return {
    vaultId: 'vault-1',
    recordId: 'rec-1',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
    ...overrides,
  };
}

describe('deriveRecordKey', () => {
  it('is deterministic for the same inputs', async () => {
    const vaultKey = randomVaultKey();
    const first = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v',
      recordId: 'r',
      recordType: 'item',
      keyVersion: 1,
    });
    const second = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v',
      recordId: 'r',
      recordType: 'item',
      keyVersion: 1,
    });
    expect(first.length).toBe(32);
    expect(constantTimeEquals(first, second)).toBe(true);
  });

  it('differs if the vault key differs', async () => {
    const a = await deriveRecordKey({
      vaultEncryptionKey: randomVaultKey(),
      vaultId: 'v',
      recordId: 'r',
      recordType: 'item',
      keyVersion: 1,
    });
    const b = await deriveRecordKey({
      vaultEncryptionKey: randomVaultKey(),
      vaultId: 'v',
      recordId: 'r',
      recordType: 'item',
      keyVersion: 1,
    });
    expect(constantTimeEquals(a, b)).toBe(false);
  });

  it('differs for every derivation-input field', async () => {
    const vaultKey = randomVaultKey();
    const base = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v',
      recordId: 'r',
      recordType: 'item',
      keyVersion: 1,
    });
    const mutations = [
      { vaultId: 'v2' },
      { recordId: 'r2' },
      { recordType: 'category' as const },
      { keyVersion: 2 },
    ];
    for (const mutation of mutations) {
      const mutated = await deriveRecordKey({
        vaultEncryptionKey: vaultKey,
        vaultId: 'v',
        recordId: 'r',
        recordType: 'item',
        keyVersion: 1,
        ...mutation,
      });
      expect(constantTimeEquals(base, mutated)).toBe(false);
    }
  });

  it('rejects a short vault encryption key', async () => {
    await expect(
      deriveRecordKey({
        vaultEncryptionKey: new Uint8Array(4),
        vaultId: 'v',
        recordId: 'r',
        recordType: 'item',
        keyVersion: 1,
      }),
    ).rejects.toBeInstanceOf(VaultCryptoError);
  });
});

describe('sealRecord / openRecord', () => {
  it('round-trips a plaintext', async () => {
    const vaultKey = randomVaultKey();
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const plaintext = encoder.encode(JSON.stringify({ title: 'Gmail', password: 'hunter2' }));
    const sealed = await sealRecord({
      plaintext,
      recordKey,
      aadInput: sampleAadInput(),
    });
    const opened = await openRecord({
      sealed,
      recordKey,
      expectedAadInput: sampleAadInput(),
    });
    expect(decoder.decode(opened.plaintext)).toBe(decoder.decode(plaintext));
  });

  it('refuses to decrypt if the expected AAD does not match the sealed AAD', async () => {
    const vaultKey = randomVaultKey();
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const sealed = await sealRecord({
      plaintext: encoder.encode('x'),
      recordKey,
      aadInput: sampleAadInput({ recordVersion: 1 }),
    });
    await expect(
      openRecord({
        sealed,
        recordKey,
        expectedAadInput: sampleAadInput({ recordVersion: 2 }),
      }),
    ).rejects.toBeInstanceOf(VaultCryptoError);
  });

  it('refuses to decrypt if the ciphertext was tampered with', async () => {
    const vaultKey = randomVaultKey();
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const sealed = await sealRecord({
      plaintext: encoder.encode('hello'),
      recordKey,
      aadInput: sampleAadInput(),
    });
    // Flip one bit of the ciphertext.
    const tamperedCiphertext = decodeBase64Url(sealed.ciphertextB64Url);
    tamperedCiphertext[0] ^= 0x01;
    const { encodeBase64Url } = await import('../canonicalJson');
    const tamperedSealed = {
      ...sealed,
      ciphertextB64Url: encodeBase64Url(tamperedCiphertext),
    };
    await expect(
      openRecord({
        sealed: tamperedSealed,
        recordKey,
        expectedAadInput: sampleAadInput(),
      }),
    ).rejects.toBeInstanceOf(VaultCryptoError);
  });

  it('refuses to decrypt if the ciphertext hash on the envelope is stale', async () => {
    const vaultKey = randomVaultKey();
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const sealed = await sealRecord({
      plaintext: encoder.encode('hello'),
      recordKey,
      aadInput: sampleAadInput(),
    });
    const poisoned = { ...sealed, ciphertextHash: 'definitely-not-the-hash' };
    await expect(
      openRecord({
        sealed: poisoned,
        recordKey,
        expectedAadInput: sampleAadInput(),
      }),
    ).rejects.toBeInstanceOf(VaultCryptoError);
  });

  it('refuses to decrypt if a second record key is used', async () => {
    const vaultKey = randomVaultKey();
    const recordKeyA = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const recordKeyB = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r2',
      recordType: 'item',
      keyVersion: 1,
    });
    const sealed = await sealRecord({
      plaintext: encoder.encode('hello'),
      recordKey: recordKeyA,
      aadInput: sampleAadInput(),
    });
    await expect(
      openRecord({
        sealed,
        recordKey: recordKeyB,
        expectedAadInput: sampleAadInput(),
      }),
    ).rejects.toBeInstanceOf(VaultCryptoError);
  });

  it('produces unique nonces across seals', async () => {
    const vaultKey = randomVaultKey();
    const recordKey = await deriveRecordKey({
      vaultEncryptionKey: vaultKey,
      vaultId: 'v1',
      recordId: 'r1',
      recordType: 'item',
      keyVersion: 1,
    });
    const a = await sealRecord({
      plaintext: encoder.encode('a'),
      recordKey,
      aadInput: sampleAadInput(),
    });
    const b = await sealRecord({
      plaintext: encoder.encode('a'),
      recordKey,
      aadInput: sampleAadInput(),
    });
    expect(a.nonceB64Url).not.toBe(b.nonceB64Url);
    expect(a.ciphertextB64Url).not.toBe(b.ciphertextB64Url);
  });
});
