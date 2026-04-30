import { describe, expect, it } from "vitest";

import {
  buildDisplayedIntegrityResult,
  buildVaultQuarantineSummary,
} from "../vaultQuarantineOrchestrator";

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

  it("treats all-item runtime decrypt failures as a key/state mismatch instead of mass quarantine", () => {
    const displayed = buildDisplayedIntegrityResult(
      {
        valid: true,
        isFirstCheck: false,
        computedRoot: "root",
        itemCount: 2,
        categoryCount: 0,
        mode: "healthy",
        quarantinedItems: [],
      },
      [
        { id: "item-a", reason: "decrypt_failed", updatedAt: null },
        { id: "item-b", reason: "decrypt_failed", updatedAt: null },
      ],
    );

    expect(displayed).toMatchObject({
      valid: false,
      mode: "revalidation_failed",
      nonTamperReason: "revalidation_failed",
      quarantinedItems: [],
    });
  });

  it("keeps a single runtime decrypt failure visible as item quarantine", () => {
    const displayed = buildDisplayedIntegrityResult(
      {
        valid: true,
        isFirstCheck: false,
        computedRoot: "root",
        itemCount: 2,
        categoryCount: 0,
        mode: "healthy",
        quarantinedItems: [],
      },
      [{ id: "item-a", reason: "decrypt_failed", updatedAt: null }],
    );

    expect(displayed).toMatchObject({
      valid: true,
      mode: "quarantine",
      quarantinedItems: [expect.objectContaining({ id: "item-a" })],
    });
  });
});
