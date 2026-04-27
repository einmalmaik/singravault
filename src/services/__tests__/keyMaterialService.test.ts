// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Unit tests for keyMaterialService.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

function createChainable(resolvedValue: unknown = { data: null, error: null }) {
  const chain: Record<string, (...args: unknown[]) => unknown> = {};
  const methods = ["select", "insert", "update", "upsert", "delete", "eq", "is", "in", "single", "maybeSingle", "limit", "order", "or"];

  for (const method of methods) {
    chain[method] = vi.fn().mockReturnValue(chain);
  }

  chain.then = (resolve: (value: unknown) => unknown) => resolve(resolvedValue);
  return chain;
}

const mockSupabase = vi.hoisted(() => {
  const chains: unknown[] = [];
  let chainIndex = 0;

  return {
    from: vi.fn().mockImplementation(() => {
      const idx = chainIndex++;
      return chains[idx] || createChainable();
    }),
    _setChains: (newChains: unknown[]) => {
      chains.length = 0;
      chains.push(...newChains);
      chainIndex = 0;
    },
    _reset: () => {
      chains.length = 0;
      chainIndex = 0;
    },
  };
});

const mockCryptoService = vi.hoisted(() => ({
  generateUserKeyPair: vi.fn().mockResolvedValue({
    publicKey: "rsa-public",
    encryptedPrivateKey: "rsa-private-encrypted",
  }),
  deriveKey: vi.fn().mockResolvedValue({} as CryptoKey),
  encrypt: vi.fn().mockResolvedValue("pq-private-encrypted"),
  generateSalt: vi.fn().mockReturnValue("pq-salt"),
}));

const mockPqService = vi.hoisted(() => ({
  generatePQKeyPair: vi.fn().mockReturnValue({
    publicKey: "pq-public",
    secretKey: "pq-secret",
  }),
}));

vi.mock("@/integrations/supabase/client", () => ({ supabase: mockSupabase }));
vi.mock("@/services/cryptoService", () => ({
  ...mockCryptoService,
  CURRENT_KDF_VERSION: 2,
}));
vi.mock("@/services/pqCryptoService", () => mockPqService);

import {
  ensureHybridKeyMaterial,
  ensureUserPqKeyMaterial,
  ensureUserRsaKeyMaterial,
  isMasterPasswordRequiredError,
} from "@/services/keyMaterialService";

beforeEach(() => {
  vi.clearAllMocks();
  mockSupabase._reset();
});

describe("ensureUserRsaKeyMaterial()", () => {
  it("returns existing RSA key material without creating new keys", async () => {
    const readChain = createChainable({
      data: { public_key: "existing-rsa-public" },
      error: null,
    });
    mockSupabase._setChains([readChain]);

    const result = await ensureUserRsaKeyMaterial({ userId: "user-1" });

    expect(result).toEqual({
      publicKey: "existing-rsa-public",
      created: false,
    });
    expect(mockCryptoService.generateUserKeyPair).not.toHaveBeenCalled();
  });

  it("requires master password when RSA keys are missing", async () => {
    const readChain = createChainable({ data: null, error: null });
    mockSupabase._setChains([readChain]);

    await expect(
      ensureUserRsaKeyMaterial({ userId: "user-1" }),
    ).rejects.toMatchObject({ code: "MASTER_PASSWORD_REQUIRED" });
  });

  it("returns winner key when concurrent insert hits unique conflict", async () => {
    const readChain = createChainable({ data: null, error: null });
    const insertChain = createChainable({ data: null, error: { code: "23505" } });
    const winnerReadChain = createChainable({
      data: { public_key: "winner-rsa-public" },
      error: null,
    });
    mockSupabase._setChains([readChain, insertChain, winnerReadChain]);

    const result = await ensureUserRsaKeyMaterial({
      userId: "user-1",
      masterPassword: "MasterPassword123!",
    });

    expect(result).toEqual({
      publicKey: "winner-rsa-public",
      created: false,
    });
  });
});

describe("ensureUserPqKeyMaterial()", () => {
  it("returns existing PQ key material without creating new keys", async () => {
    const readChain = createChainable({
      data: {
        pq_public_key: "existing-pq-public",
        pq_encrypted_private_key: "salt:ciphertext",
        pq_key_version: 1,
        pq_enforced_at: "2026-02-17T18:00:00.000Z",
        security_standard_version: 1,
        legacy_crypto_disabled_at: "2026-02-17T18:00:00.000Z",
      },
      error: null,
    });
    mockSupabase._setChains([readChain]);

    const result = await ensureUserPqKeyMaterial({ userId: "user-1" });

    expect(result).toEqual({
      publicKey: "existing-pq-public",
      created: false,
      enforcedAtSet: false,
      securityStandardApplied: false,
    });
    expect(mockPqService.generatePQKeyPair).not.toHaveBeenCalled();
  });
});

describe("ensureHybridKeyMaterial()", () => {
  it("creates missing RSA and PQ key material with one master password", async () => {
    const rsaRead = createChainable({ data: null, error: null });
    const rsaUpsert = createChainable({ data: null, error: null });
    const pqRead = createChainable({
      data: {
        pq_public_key: null,
        pq_encrypted_private_key: null,
        pq_key_version: null,
        pq_enforced_at: null,
        security_standard_version: null,
        legacy_crypto_disabled_at: null,
      },
      error: null,
    });
    const pqUpdate = createChainable({ data: { pq_public_key: "pq-public" }, error: null });
    mockSupabase._setChains([rsaRead, rsaUpsert, pqRead, pqUpdate]);

    const result = await ensureHybridKeyMaterial({
      userId: "user-1",
      masterPassword: "MasterPassword123!",
    });

    expect(result).toEqual({
      rsaPublicKey: "rsa-public",
      pqPublicKey: "pq-public",
      createdRsa: true,
      createdPq: true,
    });

    expect(mockCryptoService.generateUserKeyPair).toHaveBeenCalledWith("MasterPassword123!", 1);
    expect(mockPqService.generatePQKeyPair).toHaveBeenCalledTimes(1);
    expect(mockCryptoService.deriveKey).toHaveBeenCalledWith("MasterPassword123!", "pq-salt", 2);
    expect(mockCryptoService.encrypt).toHaveBeenCalledWith("pq-secret", expect.anything());
    expect(pqUpdate.update).toHaveBeenCalledWith(expect.objectContaining({
      pq_public_key: "pq-public",
      pq_encrypted_private_key: "2:pq-salt:pq-private-encrypted",
      pq_key_version: 1,
      security_standard_version: 1,
    }));
  });

  it("exposes helper for master password requirement errors", async () => {
    const rsaRead = createChainable({ data: null, error: null });
    mockSupabase._setChains([rsaRead]);

    let thrown: unknown = null;
    try {
      await ensureHybridKeyMaterial({ userId: "user-1" });
    } catch (error) {
      thrown = error;
    }

    expect(isMasterPasswordRequiredError(thrown)).toBe(true);
  });

  it("keeps the winner PQ key when conditional update loses a race", async () => {
    const rsaRead = createChainable({ data: { public_key: "existing-rsa-public" }, error: null });
    const pqRead = createChainable({
      data: {
        pq_public_key: null,
        pq_encrypted_private_key: null,
        pq_key_version: null,
        pq_enforced_at: null,
        security_standard_version: null,
        legacy_crypto_disabled_at: null,
      },
      error: null,
    });
    const pqClaimUpdate = createChainable({ data: null, error: null });
    const pqWinnerRead = createChainable({
      data: {
        pq_public_key: "winner-pq-public",
        pq_encrypted_private_key: "winner-salt:winner-cipher",
        pq_key_version: 1,
        pq_enforced_at: "2026-02-17T18:00:00.000Z",
        security_standard_version: 1,
        legacy_crypto_disabled_at: "2026-02-17T18:00:00.000Z",
      },
      error: null,
    });
    mockSupabase._setChains([rsaRead, pqRead, pqClaimUpdate, pqWinnerRead]);

    const result = await ensureHybridKeyMaterial({
      userId: "user-1",
      masterPassword: "MasterPassword123!",
    });

    expect(result).toEqual({
      rsaPublicKey: "existing-rsa-public",
      pqPublicKey: "winner-pq-public",
      createdRsa: false,
      createdPq: false,
    });
  });
});
