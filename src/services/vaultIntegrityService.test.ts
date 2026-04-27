import { beforeEach, describe, expect, it, vi } from "vitest";

const secretStoreState = vi.hoisted(() => ({
  baselineEnvelopes: new Map<string, string>(),
  legacySecrets: new Map<string, string>(),
}));

vi.mock("./integrityBaselineStore", () => ({
  saveIntegrityBaselineEnvelope: async (userId: string, value: string) => {
    secretStoreState.baselineEnvelopes.set(userId, value);
  },
  loadIntegrityBaselineEnvelope: async (userId: string) => secretStoreState.baselineEnvelopes.get(userId) ?? null,
  removeIntegrityBaselineEnvelope: async (userId: string) => {
    secretStoreState.baselineEnvelopes.delete(userId);
  },
}));

vi.mock("@/platform/localSecretStore", () => ({
  loadLocalSecretString: async (key: string) => secretStoreState.legacySecrets.get(key) ?? null,
  removeLocalSecret: async (key: string) => {
    secretStoreState.legacySecrets.delete(key);
  },
}));

describe("vaultIntegrityService", () => {
  beforeEach(() => {
    secretStoreState.baselineEnvelopes.clear();
    secretStoreState.legacySecrets.clear();
  });

  it("establishes a baseline on first verification", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-1", icon: null, color: "enc-blue" }],
    }, key);

    expect(result.valid).toBe(true);
    expect(result.isFirstCheck).toBe(true);
  });

  it("quarantines ciphertext drift instead of treating it as healthy", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-1", icon: null, color: "enc-blue" }],
    }, key);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-2" }],
      categories: [{ id: "cat-1", name: "enc-1", icon: null, color: "enc-blue" }],
    }, key);

    expect(result.valid).toBe(true);
    expect(result.isFirstCheck).toBe(false);
    expect(result.storedRoot).toBeDefined();
    expect(result.mode).toBe("quarantine");
    expect(result.quarantinedItems).toEqual([
      expect.objectContaining({
        id: "item-1",
        reason: "ciphertext_changed",
      }),
    ]);
  });

  it("re-baselines only trusted local item changes while preserving unrelated quarantine drift", async () => {
    const {
      persistTrustedMutationIntegrityBaseline,
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-edited", encrypted_data: "cipher-old" },
        { id: "item-tampered", encrypted_data: "cipher-safe" },
      ],
      categories: [],
    }, key);

    await persistTrustedMutationIntegrityBaseline("user-1", {
      items: [
        { id: "item-edited", encrypted_data: "cipher-new" },
        { id: "item-tampered", encrypted_data: "cipher-tampered" },
      ],
      categories: [],
    }, key, {
      itemIds: ["item-edited"],
    });

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-edited", encrypted_data: "cipher-new" },
        { id: "item-tampered", encrypted_data: "cipher-tampered" },
      ],
      categories: [],
    }, key);

    expect(result.mode).toBe("quarantine");
    expect(result.quarantinedItems).toEqual([
      expect.objectContaining({
        id: "item-tampered",
        reason: "ciphertext_changed",
      }),
    ]);
  });

  it("adds a trusted newly created item to the baseline without trusting unrelated drift", async () => {
    const {
      persistTrustedMutationIntegrityBaseline,
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-tampered", encrypted_data: "cipher-safe" }],
      categories: [],
    }, key);

    await persistTrustedMutationIntegrityBaseline("user-1", {
      items: [
        { id: "item-new", encrypted_data: "cipher-new" },
        { id: "item-tampered", encrypted_data: "cipher-tampered" },
      ],
      categories: [],
    }, key, {
      itemIds: ["item-new"],
    });

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-new", encrypted_data: "cipher-new" },
        { id: "item-tampered", encrypted_data: "cipher-tampered" },
      ],
      categories: [],
    }, key);

    expect(result.mode).toBe("quarantine");
    expect(result.quarantinedItems).toEqual([
      expect.objectContaining({
        id: "item-tampered",
        reason: "ciphertext_changed",
      }),
    ]);
  });

  it("keeps a trusted selective category re-baseline healthy on the next full verification", async () => {
    const {
      persistTrustedMutationIntegrityBaseline,
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-old", icon: null, color: "enc-blue" }],
    }, key);

    await persistTrustedMutationIntegrityBaseline("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-new", icon: null, color: "enc-blue" }],
    }, key, {
      categoryIds: ["cat-1"],
    });

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-new", icon: null, color: "enc-blue" }],
    }, key);

    expect(result.mode).toBe("healthy");
    expect(result.quarantinedItems).toEqual([]);
  });

  it("quarantines missing and unknown items against a stored V2 baseline", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-1", encrypted_data: "cipher-1" },
        { id: "item-2", encrypted_data: "cipher-2" },
      ],
      categories: [],
    }, key);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-1", encrypted_data: "cipher-1" },
        { id: "item-3", encrypted_data: "cipher-3" },
      ],
      categories: [],
    }, key);

    expect(result.mode).toBe("quarantine");
    expect(result.quarantinedItems).toEqual([
      expect.objectContaining({
        id: "item-2",
        reason: "missing_on_server",
      }),
      expect.objectContaining({
        id: "item-3",
        reason: "unknown_on_server",
      }),
    ]);
  });

  it("inspects category drift together with item drift for trusted re-baselining decisions", async () => {
    const {
      inspectVaultSnapshotIntegrity,
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-1", icon: null, color: "enc-blue" }],
    }, key);

    const inspection = await inspectVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-2", encrypted_data: "cipher-2" }],
      categories: [{ id: "cat-1", name: "enc-rotated", icon: null, color: "enc-blue" }],
    }, key);

    expect(inspection.categoryDriftIds).toEqual(["cat-1"]);
    expect(inspection.itemDrifts).toEqual([
      expect.objectContaining({
        id: "item-1",
        reason: "missing_on_server",
      }),
      expect.objectContaining({
        id: "item-2",
        reason: "unknown_on_server",
      }),
    ]);
  });

  it("blocks structurally malformed snapshots", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [
        { id: "item-1", encrypted_data: "cipher-1" },
        { id: "item-1", encrypted_data: "cipher-2" },
      ],
      categories: [],
    }, key);

    expect(result.valid).toBe(false);
    expect(result.mode).toBe("blocked");
    expect(result.blockedReason).toBe("snapshot_malformed");
  });

  it("rejects an unreadable stored integrity baseline instead of treating it as first check", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [],
    }, key);

    secretStoreState.baselineEnvelopes.set("user-1", "not-a-valid-ciphertext");

    await expect(
      verifyVaultSnapshotIntegrity("user-1", {
        items: [{ id: "item-1", encrypted_data: "cipher-1" }],
        categories: [],
      }, key),
    ).rejects.toThrow("Stored integrity baseline could not be decrypted.");
  });

  it("migrates a legacy baseline from the old local secret store", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [],
    }, key);

    const migratedPayload = secretStoreState.baselineEnvelopes.get("user-1");
    expect(migratedPayload).toBeDefined();

    secretStoreState.baselineEnvelopes.clear();
    secretStoreState.legacySecrets.set("vault-integrity:user-1", migratedPayload!);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [],
    }, key);

    expect(result.mode).toBe("healthy");
    expect(secretStoreState.baselineEnvelopes.get("user-1")).toBe(migratedPayload);
    expect(secretStoreState.legacySecrets.has("vault-integrity:user-1")).toBe(false);
  });

  it("blocks a mismatched V1 baseline during migration instead of re-blessing it", async () => {
    const {
      computeVaultSnapshotDigest,
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");
    const { encrypt } = await import("./cryptoService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    const originalSnapshot = {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [],
    };
    const originalDigest = await computeVaultSnapshotDigest(originalSnapshot);
    const legacyEnvelope = await encrypt(JSON.stringify({
      version: 1,
      digest: originalDigest,
      itemCount: 1,
      categoryCount: 0,
      recordedAt: new Date().toISOString(),
    }), key);

    secretStoreState.legacySecrets.set("vault-integrity:user-1", legacyEnvelope);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-2" }],
      categories: [],
    }, key);

    expect(result.valid).toBe(false);
    expect(result.mode).toBe("blocked");
    expect(result.blockedReason).toBe("legacy_baseline_mismatch");
    expect(secretStoreState.baselineEnvelopes.get("user-1")).toBe(legacyEnvelope);
  });
});
