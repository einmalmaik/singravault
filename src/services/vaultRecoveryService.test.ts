import { beforeEach, describe, expect, it, vi } from "vitest";

const supabaseState = vi.hoisted(() => ({
  rpcCalls: [] as Array<{ name: string; args?: Record<string, unknown> }>,
}));

const dependencyMocks = vi.hoisted(() => ({
  clearOfflineVaultData: vi.fn(async () => undefined),
  clearIntegrityBaseline: vi.fn(async () => undefined),
  deleteDeviceKey: vi.fn(async () => undefined),
}));

vi.mock("@/integrations/supabase/client", () => ({
  supabase: {
    rpc: async (name: string, args?: Record<string, unknown>) => {
      supabaseState.rpcCalls.push({ name, args });
      return { data: { reset: true }, error: null };
    },
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
    supabaseState.rpcCalls.length = 0;
    dependencyMocks.clearOfflineVaultData.mockClear();
    dependencyMocks.clearIntegrityBaseline.mockClear();
    dependencyMocks.deleteDeviceKey.mockClear();
  });

  it("uses the atomic remote reset before clearing local vault state", async () => {
    await resetUserVaultState("user-1");

    expect(supabaseState.rpcCalls).toEqual([{ name: "reset_user_vault_state", args: undefined }]);
    expect(dependencyMocks.clearOfflineVaultData).toHaveBeenCalledWith("user-1");
    expect(dependencyMocks.clearIntegrityBaseline).toHaveBeenCalledWith("user-1");
    expect(dependencyMocks.deleteDeviceKey).toHaveBeenCalledWith("user-1");
  });
});
