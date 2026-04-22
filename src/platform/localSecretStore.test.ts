import { beforeEach, describe, expect, it, vi } from "vitest";

const runtimeState = vi.hoisted(() => ({
  isTauri: false,
  invoke: vi.fn(),
}));

vi.mock("./runtime", () => ({
  isTauriRuntime: () => runtimeState.isTauri,
}));

vi.mock("./tauriInvoke", () => ({
  getTauriInvoke: async () => (runtimeState.isTauri ? runtimeState.invoke : null),
}));

describe("localSecretStore", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    runtimeState.isTauri = false;
  });

  it("stores and loads browser secrets", async () => {
    const store = await import("./localSecretStore");

    await store.saveLocalSecretString("integrity:test", "payload-123");
    await expect(store.loadLocalSecretString("integrity:test")).resolves.toBe("payload-123");
  });

  it("removes browser secrets", async () => {
    const store = await import("./localSecretStore");

    await store.saveLocalSecretString("integrity:test", "payload-123");
    await store.removeLocalSecret("integrity:test");

    await expect(store.loadLocalSecretString("integrity:test")).resolves.toBeNull();
  });

  it("uses tauri invoke commands in desktop runtime", async () => {
    runtimeState.isTauri = true;
    runtimeState.invoke.mockResolvedValueOnce(undefined);
    runtimeState.invoke.mockResolvedValueOnce("c2VjcmV0");
    runtimeState.invoke.mockResolvedValueOnce(undefined);

    const store = await import("./localSecretStore");

    await store.saveLocalSecretBytes("device-key:test", new Uint8Array([115, 101, 99, 114, 101, 116]));
    const loaded = await store.loadLocalSecretBytes("device-key:test");
    await store.removeLocalSecret("device-key:test");

    expect(Array.from(loaded ?? [])).toEqual([115, 101, 99, 114, 101, 116]);
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(1, "save_local_secret", {
      key: "device-key:test",
      value: "c2VjcmV0",
    });
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(2, "load_local_secret", {
      key: "device-key:test",
    });
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(3, "clear_local_secret", {
      key: "device-key:test",
    });
  });
});
