import { describe, expect, it } from "vitest";

import { buildVaultQuarantineSummary } from "../vaultQuarantineOrchestrator";

describe("vaultQuarantineOrchestrator", () => {
  it("keeps quarantined item ids out of the decryptable set", () => {
    const summary = buildVaultQuarantineSummary(
      [{ id: "item-b", reason: "decrypt_failed", updatedAt: null }],
      ["item-a", "item-b", "item-c"],
    );

    expect(summary.quarantinedItems).toEqual([
      expect.objectContaining({ id: "item-b" }),
    ]);
    expect(summary.decryptableItemIds).toEqual(["item-a", "item-c"]);
  });
});
