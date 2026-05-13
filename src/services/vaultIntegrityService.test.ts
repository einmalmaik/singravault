import { describe, expect, it } from "vitest";

import {
  clearIntegrityRoot,
  deriveIntegrityKey,
  updateIntegrityRoot,
  verifyVaultIntegrity,
} from "./vaultIntegrityService";

describe("vaultIntegrityService", () => {
  it("Phase 11: old baseline/digest trust functions stay unavailable", async () => {
    // verifyVaultSnapshotIntegrity, inspectVaultSnapshotIntegrity,
    // persistIntegrityBaseline, computeVaultSnapshotDigest, etc.
    // were removed in Phase 11. Legacy premium exports exist only for
    // build compatibility and must fail closed if called.
    await expect(deriveIntegrityKey("password", "salt")).rejects.toThrow(
      "Legacy vault integrity adapter is disabled",
    );

    await expect(
      verifyVaultIntegrity([], {} as CryptoKey, "user-1"),
    ).rejects.toThrow("Legacy vault integrity adapter is disabled");

    await expect(
      updateIntegrityRoot([], {} as CryptoKey, "user-1"),
    ).rejects.toThrow("Legacy vault integrity adapter is disabled");

    expect(() => clearIntegrityRoot("user-1")).not.toThrow();
  });
});
