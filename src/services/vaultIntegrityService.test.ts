import { beforeEach, describe, expect, it, vi } from "vitest";

const secretStoreState = vi.hoisted(() => ({
  secrets: new Map<string, string>(),
}));

vi.mock("@/platform/localSecretStore", () => ({
  saveLocalSecretString: async (key: string, value: string) => {
    secretStoreState.secrets.set(key, value);
  },
  loadLocalSecretString: async (key: string) => secretStoreState.secrets.get(key) ?? null,
  removeLocalSecret: async (key: string) => {
    secretStoreState.secrets.delete(key);
  },
}));

describe("vaultIntegrityService", () => {
  beforeEach(() => {
    secretStoreState.secrets.clear();
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

  it("detects tampering when the encrypted snapshot changes", async () => {
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

    expect(result.valid).toBe(false);
    expect(result.isFirstCheck).toBe(false);
    expect(result.storedRoot).toBeDefined();
  });
});
