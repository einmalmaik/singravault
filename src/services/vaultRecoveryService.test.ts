import { beforeEach, describe, expect, it, vi } from "vitest";

const supabaseState = vi.hoisted(() => ({
  deletes: [] as Array<{ table: string; column: string; value: string }>,
  updates: [] as Array<{ table: string; payload: Record<string, unknown>; column: string; value: string }>,
}));

const dependencyMocks = vi.hoisted(() => ({
  clearOfflineVaultData: vi.fn(async () => undefined),
  clearIntegrityBaseline: vi.fn(async () => undefined),
  deleteDeviceKey: vi.fn(async () => undefined),
}));

vi.mock("@/integrations/supabase/client", () => ({
  supabase: {
    from: (table: string) => ({
      delete: () => ({
        eq: async (column: string, value: string) => {
          supabaseState.deletes.push({ table, column, value });
          return { error: null };
        },
      }),
      update: (payload: Record<string, unknown>) => ({
        eq: async (column: string, value: string) => {
          supabaseState.updates.push({ table, payload, column, value });
          return { error: null };
        },
      }),
    }),
  },
}));

vi.mock("@/services/offlineVaultService", () => ({
  clearOfflineVaultData: dependencyMocks.clearOfflineVaultData,
}));

vi.mock("@/services/vaultIntegrityService", () => ({
  clearIntegrityBaseline: dependencyMocks.clearIntegrityBaseline,
}));

vi.mock("@/services/deviceKeyService", () => ({
  deleteDeviceKey: dependencyMocks.deleteDeviceKey,
}));

import { resetUserVaultState } from "@/services/vaultRecoveryService";

describe("vaultRecoveryService", () => {
  beforeEach(() => {
    supabaseState.deletes.length = 0;
    supabaseState.updates.length = 0;
    dependencyMocks.clearOfflineVaultData.mockClear();
    dependencyMocks.clearIntegrityBaseline.mockClear();
    dependencyMocks.deleteDeviceKey.mockClear();
  });

  it("keeps auth passkeys and only clears their vault unlock material", async () => {
    await resetUserVaultState("user-1");

    expect(supabaseState.deletes.map((entry) => entry.table)).not.toContain("passkey_credentials");
    expect(supabaseState.updates).toContainEqual(expect.objectContaining({
      table: "passkey_credentials",
      column: "user_id",
      value: "user-1",
      payload: expect.objectContaining({
        wrapped_master_key: null,
        prf_enabled: false,
      }),
    }));
    expect(dependencyMocks.clearOfflineVaultData).toHaveBeenCalledWith("user-1");
    expect(dependencyMocks.clearIntegrityBaseline).toHaveBeenCalledWith("user-1");
    expect(dependencyMocks.deleteDeviceKey).toHaveBeenCalledWith("user-1");
  });
});
