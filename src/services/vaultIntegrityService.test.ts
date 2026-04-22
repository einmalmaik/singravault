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

  it("quarantines a tampered item without blocking the whole vault", async () => {
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

  it("blocks unlock when category integrity no longer matches", async () => {
    const {
      verifyVaultSnapshotIntegrity,
    } = await import("./vaultIntegrityService");

    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

    await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-1", icon: null, color: "enc-blue" }],
    }, key);

    const result = await verifyVaultSnapshotIntegrity("user-1", {
      items: [{ id: "item-1", encrypted_data: "cipher-1" }],
      categories: [{ id: "cat-1", name: "enc-2", icon: null, color: "enc-blue" }],
    }, key);

    expect(result.valid).toBe(false);
    expect(result.mode).toBe("blocked");
    expect(result.blockedReason).toBe("category_structure_mismatch");
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
});
