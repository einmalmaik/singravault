import { beforeEach, describe, expect, it, vi } from "vitest";

const localSecretState = vi.hoisted(() => ({
  supported: true,
  store: new Map<string, Uint8Array>(),
}));

vi.mock("@/platform/localSecretStore", () => ({
  isLocalSecretStoreSupported: vi.fn(async () => localSecretState.supported),
  saveLocalSecretBytes: vi.fn(async (key: string, value: Uint8Array) => {
    localSecretState.store.set(key, new Uint8Array(value));
  }),
  loadLocalSecretBytes: vi.fn(async (key: string) => {
    const value = localSecretState.store.get(key);
    return value ? new Uint8Array(value) : null;
  }),
  removeLocalSecret: vi.fn(async (key: string) => {
    localSecretState.store.delete(key);
  }),
}));

import {
  deleteDeviceKey,
  exportDeviceKeyForTransfer,
  generateDeviceKey,
  getDeviceKey,
  hasDeviceKey,
  importDeviceKeyFromTransfer,
  storeDeviceKey,
} from "@/services/deviceKeyService";

describe("deviceKeyService", () => {
  beforeEach(() => {
    localSecretState.supported = true;
    localSecretState.store.clear();
  });

  it("stores and loads device keys through the local secret store", async () => {
    const deviceKey = new Uint8Array(32).fill(7);

    await storeDeviceKey("user-1", deviceKey);

    await expect(getDeviceKey("user-1")).resolves.toEqual(deviceKey);
    await expect(hasDeviceKey("user-1")).resolves.toBe(true);
  });

  it("rejects storing a device key when secure local storage is unavailable", async () => {
    localSecretState.supported = false;

    await expect(storeDeviceKey("user-1", generateDeviceKey())).rejects.toThrow(
      "Secure local secret storage is not available in this runtime.",
    );
    await expect(hasDeviceKey("user-1")).resolves.toBe(false);
  });

  it("deletes stored device keys", async () => {
    await storeDeviceKey("user-1", new Uint8Array(32).fill(9));
    await deleteDeviceKey("user-1");

    await expect(getDeviceKey("user-1")).resolves.toBeNull();
    await expect(hasDeviceKey("user-1")).resolves.toBe(false);
  });

  it("exports and imports device keys with PIN-based transfer encryption", async () => {
    const original = new Uint8Array(32);
    for (let index = 0; index < original.length; index += 1) {
      original[index] = index + 1;
    }

    await storeDeviceKey("user-1", original);
    const transferData = await exportDeviceKeyForTransfer("user-1", "123456");

    expect(transferData).toEqual(expect.any(String));

    await deleteDeviceKey("user-1");
    await expect(importDeviceKeyFromTransfer("user-1", transferData!, "123456")).resolves.toBe(true);
    await expect(getDeviceKey("user-1")).resolves.toEqual(original);
  });

  it("rejects import when the transfer PIN is wrong", async () => {
    const original = new Uint8Array(32).fill(5);
    await storeDeviceKey("user-1", original);

    const transferData = await exportDeviceKeyForTransfer("user-1", "123456");
    await deleteDeviceKey("user-1");

    await expect(importDeviceKeyFromTransfer("user-1", transferData!, "654321")).resolves.toBe(false);
    await expect(getDeviceKey("user-1")).resolves.toBeNull();
  });
});
