import { describe, expect, it } from "vitest";

import {
  assessVaultIntegritySnapshot,
  buildSnapshotCompletenessContext,
  buildVaultIntegritySnapshot,
  canRebaselineTrustedMutation,
  decideVaultIntegrity,
  normalizeTrustedVaultMutation,
} from "../vaultIntegrityDecisionEngine";
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

  it("treats incomplete snapshot drift as scope_incomplete instead of item quarantine", () => {
    const completeness = buildSnapshotCompletenessContext({
      source: "remote",
      snapshot: {
        userId: "user-1",
        vaultId: "vault-1",
        items: [{ id: "item-1" }],
        categories: [],
        lastSyncedAt: "2026-04-29T10:00:00.000Z",
        updatedAt: "2026-04-29T10:00:00.000Z",
        completeness: {
          kind: "scope_incomplete",
          reason: "pagination_count_mismatch",
          checkedAt: "2026-04-29T10:00:00.000Z",
          source: "remote",
          scope: {
            kind: "private_default_vault",
            userId: "user-1",
            vaultId: "vault-1",
            includesSharedCollections: false,
          },
          vault: { defaultVaultResolved: true },
          items: {
            loadedCount: 1,
            totalCount: 2,
            complete: false,
            pageSize: 1000,
          },
          categories: {
            loadedCount: 0,
            totalCount: 0,
            complete: true,
            pageSize: 1000,
          },
        },
      } as never,
    });

    const decision = decideVaultIntegrity({
      inspection: {
        ...healthyInspection,
        nonTamperState: completeness.nonTamperState,
        itemDrifts: [{ id: "item-2", reason: "missing_on_server", updatedAt: null }],
      },
    });

    expect(decision.mode).toBe("scope_incomplete");
    expect(decision.quarantinedItems).toEqual([]);
    expect(decision.debugSafeReason).toBe("snapshot_scope_incomplete");
  });

  it("accepts a cached snapshot as scope-complete only when its cached completeness was remote-verified", () => {
    const completeness = buildSnapshotCompletenessContext({
      source: "cache",
      snapshot: {
        userId: "user-1",
        vaultId: "vault-1",
        items: [{ id: "item-1" }],
        categories: [],
        lastSyncedAt: "2026-04-29T10:00:00.000Z",
        updatedAt: "2026-04-29T10:00:00.000Z",
        completeness: {
          kind: "complete",
          reason: "remote_page_count_verified",
          checkedAt: "2026-04-29T10:00:00.000Z",
          source: "remote",
          scope: {
            kind: "private_default_vault",
            userId: "user-1",
            vaultId: "vault-1",
            includesSharedCollections: false,
          },
          vault: { defaultVaultResolved: true },
          items: {
            loadedCount: 1,
            totalCount: 1,
            complete: true,
            pageSize: 1000,
          },
          categories: {
            loadedCount: 0,
            totalCount: 0,
            complete: true,
            pageSize: 1000,
          },
        },
      } as never,
    });

    expect(completeness).toEqual({
      isComplete: true,
      canVerifyDrift: true,
    });
  });

  it("does not create a first offline trust baseline from a non-empty cached snapshot", async () => {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const assessment = await assessVaultIntegritySnapshot({
      userId: "user-without-baseline",
      activeKey: key,
      source: "cache",
      snapshot: {
        userId: "user-without-baseline",
        vaultId: "vault-1",
        items: [{
          id: "item-1",
          user_id: "user-without-baseline",
          vault_id: "vault-1",
          title: "",
          website_url: null,
          icon_url: null,
          item_type: "password",
          category_id: null,
          is_favorite: null,
          sort_order: null,
          last_used_at: null,
          encrypted_data: "ciphertext",
          created_at: "2026-04-29T10:00:00.000Z",
          updated_at: "2026-04-29T10:00:00.000Z",
        }],
        categories: [],
        lastSyncedAt: "2026-04-29T10:00:00.000Z",
        updatedAt: "2026-04-29T10:00:00.000Z",
        completeness: {
          kind: "complete",
          reason: "remote_page_count_verified",
          checkedAt: "2026-04-29T10:00:00.000Z",
          source: "remote",
          scope: {
            kind: "private_default_vault",
            userId: "user-without-baseline",
            vaultId: "vault-1",
            includesSharedCollections: false,
          },
          vault: { defaultVaultResolved: true },
          items: {
            loadedCount: 1,
            totalCount: 1,
            complete: true,
            pageSize: 1000,
          },
          categories: {
            loadedCount: 0,
            totalCount: 0,
            complete: true,
            pageSize: 1000,
          },
        },
      },
    });

    expect(assessment.result.mode).toBe("integrity_unknown");
    expect(assessment.result.nonTamperReason).toBe("snapshot_source_not_authoritative");
  });

  it("reports incompatible baseline versions as migration_required without all-items quarantine", () => {
    const decision = decideVaultIntegrity({
      inspection: {
        ...healthyInspection,
        nonTamperState: {
          mode: "migration_required",
          reason: "baseline_canonicalization_incompatible",
        },
        itemDrifts: [
          { id: "item-1", reason: "ciphertext_changed", updatedAt: null },
          { id: "item-2", reason: "missing_on_server", updatedAt: null },
        ],
      },
    });

    expect(decision.mode).toBe("migration_required");
    expect(decision.quarantinedItems).toEqual([]);
    expect(decision.debugSafeReason).toBe("baseline_canonicalization_incompatible");
  });

  it("canonicalizes nullable category metadata deterministically", () => {
    const snapshot = buildVaultIntegritySnapshot({
      items: [{ id: "item-1", encrypted_data: "ciphertext" }],
      categories: [
        { id: "cat-1", name: "Allgemein", icon: undefined as unknown as string, color: null },
      ],
    });

    expect(snapshot.categories[0]).toEqual({
      id: "cat-1",
      name: "Allgemein",
      icon: null,
      color: null,
    });
    expect(snapshot.items[0].item_type).toBeNull();
  });

  it("allows rebaseline only for explicitly trusted drift scope", () => {
    const trustedMutation = normalizeTrustedVaultMutation({ itemIds: ["item-1"] });
    const assessment = {
      inspection: {
        ...healthyInspection,
        itemDrifts: [{ id: "item-1", reason: "ciphertext_changed" as const, updatedAt: null }],
      },
      unreadableCategoryReason: null,
    };

    expect(canRebaselineTrustedMutation(assessment, trustedMutation)).toBe(true);
    expect(canRebaselineTrustedMutation({
      ...assessment,
      inspection: {
        ...assessment.inspection,
        categoryDriftIds: ["cat-1"],
      },
    }, trustedMutation)).toBe(false);
  });
});
