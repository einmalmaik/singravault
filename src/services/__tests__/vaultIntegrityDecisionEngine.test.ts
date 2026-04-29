import { describe, expect, it } from "vitest";

import { decideVaultIntegrity } from "../vaultIntegrityDecisionEngine";
import type { VaultIntegrityBaselineInspection } from "../vaultIntegrityService";

const healthyInspection: VaultIntegrityBaselineInspection = {
  digest: "digest",
  itemCount: 1,
  categoryCount: 1,
  baselineKind: "v2",
  storedRoot: "digest",
  legacyBaselineMismatch: false,
  itemDrifts: [],
  categoryDriftIds: [],
};

describe("vaultIntegrityDecisionEngine", () => {
  it("keeps item drift in quarantine without blocking the whole vault", () => {
    const decision = decideVaultIntegrity({
      inspection: {
        ...healthyInspection,
        itemDrifts: [{ id: "item-1", reason: "ciphertext_changed", updatedAt: null }],
      },
      trustedSnapshotItemIds: ["item-1"],
    });

    expect(decision.mode).toBe("quarantine");
    expect(decision.blockedReason).toBeNull();
    expect(decision.quarantinedItems).toEqual([
      expect.objectContaining({ id: "item-1", reason: "ciphertext_changed" }),
    ]);
    expect(decision.recoverableFromTrustedSnapshot).toBe(true);
  });

  it("blocks category drift", () => {
    const decision = decideVaultIntegrity({
      inspection: {
        ...healthyInspection,
        categoryDriftIds: ["cat-1"],
      },
    });

    expect(decision.mode).toBe("blocked");
    expect(decision.blockedReason).toBe("category_structure_mismatch");
    expect(decision.driftedCategoryIds).toEqual(["cat-1"]);
  });

  it("blocks malformed snapshots", () => {
    const decision = decideVaultIntegrity({
      inspection: {
        ...healthyInspection,
        snapshotValidationError: "snapshot_malformed",
      },
    });

    expect(decision.mode).toBe("blocked");
    expect(decision.blockedReason).toBe("snapshot_malformed");
  });
});
