import { describe, expect, it } from "vitest";

import {
  buildDisplayedIntegrityResult,
  buildVaultQuarantineSummary,
} from "../vaultQuarantineOrchestrator";

describe("vaultQuarantineOrchestrator", () => {
  it("keeps only active quarantined item ids out of the decryptable set", () => {
    const summary = buildVaultQuarantineSummary(
      [
        { id: "item-b", reason: "ciphertext_changed", updatedAt: null },
        { id: "item-c", reason: "decrypt_failed", updatedAt: null },
      ],
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

  it("treats a single runtime decrypt failure as revalidation failure, not item quarantine", () => {
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
      valid: false,
      mode: "revalidation_failed",
      nonTamperReason: "revalidation_failed",
      quarantinedItems: [],
    });
  });

  it("does not merge runtime decrypt failures into persisted item quarantine", () => {
    const displayed = buildDisplayedIntegrityResult(
      {
        valid: true,
        isFirstCheck: false,
        computedRoot: "root",
        itemCount: 2,
        categoryCount: 0,
        mode: "quarantine",
        quarantinedItems: [{ id: "item-b", reason: "ciphertext_changed", updatedAt: null }],
      },
      [{ id: "item-a", reason: "decrypt_failed", updatedAt: null }],
    );

    expect(displayed).toMatchObject({
      valid: true,
      mode: "quarantine",
      quarantinedItems: [expect.objectContaining({ id: "item-b" })],
    });
  });

  it("deduplicates active quarantine and drops stale diagnostic records defensively", () => {
    const displayed = buildDisplayedIntegrityResult({
      valid: true,
      isFirstCheck: false,
      computedRoot: "root",
      itemCount: 17,
      categoryCount: 0,
      mode: "quarantine",
      quarantinedItems: [
        { id: "item-1", reason: "ciphertext_changed", updatedAt: "2026-04-22T11:00:00.000Z" },
        { id: "item-1", reason: "ciphertext_changed", updatedAt: "2026-04-22T10:00:00.000Z" },
        { id: "stale-1", reason: "missing_on_server", updatedAt: null },
        { id: "stale-2", reason: "unknown_on_server", updatedAt: null },
        { id: "runtime-1", reason: "decrypt_failed", updatedAt: null },
      ],
    });

    expect(displayed).toMatchObject({
      mode: "quarantine",
      itemCount: 17,
      quarantinedItems: [
        { id: "item-1", reason: "ciphertext_changed", updatedAt: "2026-04-22T11:00:00.000Z" },
      ],
    });
  });

  it("keeps search, category, authenticator, and health views read-only over the same decision", () => {
    const baseResult = {
      valid: true,
      isFirstCheck: false,
      computedRoot: "root",
      itemCount: 17,
      categoryCount: 3,
      mode: "healthy" as const,
      quarantinedItems: [],
    };

    const viewTransitions = ["search", "category", "authenticator", "vault-health", "all-items"];
    const displayedResults = viewTransitions.map(() => buildDisplayedIntegrityResult(baseResult));

    expect(displayedResults).toHaveLength(5);
    expect(displayedResults.every((result) => result?.mode === "healthy")).toBe(true);
    expect(displayedResults.every((result) => result?.quarantinedItems.length === 0)).toBe(true);
    expect(displayedResults.every((result) => result?.itemCount === 17)).toBe(true);
  });
});
