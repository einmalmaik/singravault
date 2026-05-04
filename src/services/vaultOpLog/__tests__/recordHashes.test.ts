// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
import { describe, expect, it } from 'vitest';
import {
  computeAadHash,
  computeCiphertextHash,
  computeOpHash,
  computeVaultHead,
  sha256Base64Url,
} from '../recordHashes';
import { buildRecordAad } from '../recordAad';
import { canonicalizeVaultStructure, decodeBase64Url } from '../canonicalJson';
import {
  DEVICE_SIGNATURE_SCHEMA_V1,
  type VaultOperationSignedBodyV1,
} from '../types';

function sampleAad() {
  return buildRecordAad({
    vaultId: 'v1',
    recordId: 'r1',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
  });
}

function sampleBody(overrides: Partial<VaultOperationSignedBodyV1> = {}): VaultOperationSignedBodyV1 {
  return {
    signatureSchema: DEVICE_SIGNATURE_SCHEMA_V1,
    opId: 'op-1',
    intentId: 'intent-1',
    rebasedFromOpId: null,
    vaultId: 'v1',
    authorDeviceId: 'dev-1',
    opType: 'create',
    recordId: 'r1',
    recordType: 'item',
    baseRecordVersion: null,
    previousCiphertextHash: null,
    newRecordHash: 'newhash',
    baseVaultHead: null,
    payloadCiphertextHash: 'cthash',
    payloadAadHash: 'aadhash',
    createdAtClient: '2026-01-01T00:00:00.000Z',
    trustEpoch: 0,
    ...overrides,
  };
}

describe('computeAadHash', () => {
  it('returns 32 base64url-decodable bytes', async () => {
    const hash = await computeAadHash(sampleAad());
    const bytes = decodeBase64Url(hash);
    expect(bytes.length).toBe(32);
  });

  it('is deterministic', async () => {
    const first = await computeAadHash(sampleAad());
    const second = await computeAadHash(sampleAad());
    expect(first).toBe(second);
  });

  it('changes when any AAD field changes', async () => {
    const base = await computeAadHash(sampleAad());
    const mutated = await computeAadHash(
      buildRecordAad({
        vaultId: 'v1',
        recordId: 'r1',
        recordType: 'item',
        recordVersion: 2,
        keyVersion: 1,
      }),
    );
    expect(mutated).not.toBe(base);
  });
});

describe('computeCiphertextHash', () => {
  const baseInput = {
    aadHash: 'aad-hash',
    nonceB64Url: 'AAAAAAAAAAAAAAAA',
    ciphertextB64Url: 'BBBBBBBB',
    vaultId: 'v1',
    recordId: 'r1',
    recordType: 'item',
    recordVersion: 1,
    keyVersion: 1,
  };

  it('is deterministic', async () => {
    const a = await computeCiphertextHash(baseInput);
    const b = await computeCiphertextHash(baseInput);
    expect(a).toBe(b);
  });

  it('detects any mutation of the ciphertext context', async () => {
    const base = await computeCiphertextHash(baseInput);
    await Promise.all(
      (Object.keys(baseInput) as Array<keyof typeof baseInput>).map(async (key) => {
        const mutated = { ...baseInput };
        if (typeof mutated[key] === 'number') {
          (mutated as Record<string, unknown>)[key] = (mutated[key] as number) + 1;
        } else {
          (mutated as Record<string, unknown>)[key] = `${mutated[key] as string}x`;
        }
        const hash = await computeCiphertextHash(mutated);
        expect(hash).not.toBe(base);
      }),
    );
  });
});

describe('computeOpHash', () => {
  it('is deterministic', async () => {
    const a = await computeOpHash(sampleBody());
    const b = await computeOpHash(sampleBody());
    expect(a).toBe(b);
  });

  it('detects every signed field', async () => {
    const base = await computeOpHash(sampleBody());
    const cases: Array<Partial<VaultOperationSignedBodyV1>> = [
      { opId: 'op-2' },
      { intentId: 'intent-2' },
      { rebasedFromOpId: 'op-prev' },
      { vaultId: 'v2' },
      { authorDeviceId: 'dev-2' },
      { opType: 'update' },
      { recordId: 'r2' },
      { recordType: 'category' },
      { baseRecordVersion: 1 },
      { previousCiphertextHash: 'hash-x' },
      { newRecordHash: 'hash-y' },
      { baseVaultHead: 'head-x' },
      { payloadCiphertextHash: 'ct-x' },
      { payloadAadHash: 'aad-x' },
      { createdAtClient: '2026-01-01T00:00:01.000Z' },
      { trustEpoch: 1 },
    ];
    for (const override of cases) {
      const mutated = await computeOpHash(sampleBody(override));
      expect(mutated).not.toBe(base);
    }
  });
});

describe('computeVaultHead', () => {
  it('chains correctly: different previous-head or different op produces a different result', async () => {
    const head0 = await computeVaultHead({
      previousVaultHead: null,
      opHash: 'op1',
      recordId: 'r1',
      recordType: 'item',
      newRecordHash: 'h1',
      opType: 'create',
    });
    const head1 = await computeVaultHead({
      previousVaultHead: head0,
      opHash: 'op2',
      recordId: 'r1',
      recordType: 'item',
      newRecordHash: 'h2',
      opType: 'update',
    });
    const head1Rewritten = await computeVaultHead({
      previousVaultHead: 'attacker-picked-head',
      opHash: 'op2',
      recordId: 'r1',
      recordType: 'item',
      newRecordHash: 'h2',
      opType: 'update',
    });
    expect(head1).not.toBe(head0);
    expect(head1).not.toBe(head1Rewritten);
  });
});

describe('sha256Base64Url', () => {
  it('matches the SHA-256 digest of the canonicalised bytes', async () => {
    const bytes = canonicalizeVaultStructure({ value: 1 });
    const digest = await sha256Base64Url(bytes);
    const decoded = decodeBase64Url(digest);
    expect(decoded.length).toBe(32);
  });
});
