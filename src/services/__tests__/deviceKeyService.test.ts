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

vi.mock("hash-wasm", () => ({
  argon2id: vi.fn(async ({
    password,
    salt,
    hashLength,
  }: {
    password: string;
    salt: Uint8Array;
    hashLength: number;
  }) => {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 1000,
        hash: "SHA-256",
      },
      keyMaterial,
      hashLength * 8,
    );

    return new Uint8Array(bits);
  }),
}));

import {
  DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH,
  deleteDeviceKey,
  deriveWithDeviceKey,
  exportDeviceKeyForTransfer,
  generateDeviceKey,
  generateDeviceKeyTransferSecret,
  getDeviceKey,
  hasDeviceKey,
  importDeviceKeyFromTransfer,
  storeDeviceKey,
} from "@/services/deviceKeyService";

const LEGACY_DB_NAME = "singra_device_keys";
const LEGACY_DB_VERSION = 1;
const LEGACY_STORE_NAME = "keys";
const TRANSFER_PREFIX = "sv-dk-transfer-v2:";

function requestToPromise<T>(request: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error);
  });
}

async function openLegacyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(LEGACY_DB_NAME, LEGACY_DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(LEGACY_STORE_NAME)) {
        db.createObjectStore(LEGACY_STORE_NAME, { keyPath: "userId" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function writeLegacyDeviceKeyRecord(userId: string, deviceKey: Uint8Array): Promise<void> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(userId),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("SINGRA_DEVICE_KEY_WRAP"),
      info: new TextEncoder().encode("device-key-wrapping"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    wrappingKey,
    deviceKey,
  );

  const db = await openLegacyDb();
  const transaction = db.transaction(LEGACY_STORE_NAME, "readwrite");
  const store = transaction.objectStore(LEGACY_STORE_NAME);
  await requestToPromise(store.put(
    {
      userId,
      iv: Array.from(iv),
      encrypted: Array.from(new Uint8Array(encrypted)),
      createdAt: new Date().toISOString(),
    },
    userId,
  ));
}

async function readLegacyDeviceKeyRecord(userId: string): Promise<unknown> {
  const db = await openLegacyDb();
  const transaction = db.transaction(LEGACY_STORE_NAME, "readonly");
  const store = transaction.objectStore(LEGACY_STORE_NAME);
  return requestToPromise(store.get(userId));
}

function decodeTransferEnvelope(transferData: string): Record<string, unknown> {
  const encoded = transferData.slice(TRANSFER_PREFIX.length);
  const bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

function encodeTransferEnvelope(envelope: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(envelope));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return `${TRANSFER_PREFIX}${btoa(binary)}`;
}

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

  it("generates 32-byte random device keys", () => {
    const first = generateDeviceKey();
    const second = generateDeviceKey();

    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toEqual(second);
  });

  it("generates strong random transfer secrets", () => {
    const first = generateDeviceKeyTransferSecret();
    const second = generateDeviceKeyTransferSecret();

    expect(first.length).toBeGreaterThanOrEqual(DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH);
    expect(second.length).toBeGreaterThanOrEqual(DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH);
    expect(first).not.toBe(second);
    expect(first).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("rejects device keys and Argon2 outputs with the wrong length", async () => {
    await expect(storeDeviceKey("user-1", new Uint8Array(31))).rejects.toThrow(
      "Device key must be exactly 32 bytes.",
    );
    await expect(deriveWithDeviceKey(new Uint8Array(32), new Uint8Array(33))).rejects.toThrow(
      "Device key must be exactly 32 bytes.",
    );
    await expect(deriveWithDeviceKey(new Uint8Array(31), new Uint8Array(32))).rejects.toThrow(
      "Argon2id output must be exactly 32 bytes.",
    );
  });

  it("derives deterministic but factor-sensitive keys", async () => {
    const masterDerived = new Uint8Array(32).fill(1);
    const otherMasterDerived = new Uint8Array(32).fill(2);
    const deviceKey = new Uint8Array(32).fill(3);
    const otherDeviceKey = new Uint8Array(32).fill(4);

    const first = await deriveWithDeviceKey(masterDerived, deviceKey);
    const second = await deriveWithDeviceKey(masterDerived, deviceKey);
    const differentDevice = await deriveWithDeviceKey(masterDerived, otherDeviceKey);
    const differentMaster = await deriveWithDeviceKey(otherMasterDerived, deviceKey);

    expect(first).toEqual(second);
    expect(first).not.toEqual(differentDevice);
    expect(first).not.toEqual(differentMaster);
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

  it("migrates legacy IndexedDB device keys into the local secret store", async () => {
    const legacyDeviceKey = new Uint8Array(32);
    for (let index = 0; index < legacyDeviceKey.length; index += 1) {
      legacyDeviceKey[index] = index + 11;
    }

    await writeLegacyDeviceKeyRecord("legacy-user", legacyDeviceKey);

    await expect(getDeviceKey("legacy-user")).resolves.toEqual(legacyDeviceKey);
    await expect(hasDeviceKey("legacy-user")).resolves.toBe(true);
    expect(localSecretState.store.get("device-key:legacy-user")).toEqual(legacyDeviceKey);
    await expect(readLegacyDeviceKeyRecord("legacy-user")).resolves.toBeUndefined();
  });

  it("still reads legacy IndexedDB device keys when migration cannot persist yet", async () => {
    const legacyDeviceKey = new Uint8Array(32).fill(13);
    localSecretState.supported = false;

    await writeLegacyDeviceKeyRecord("legacy-unsupported-user", legacyDeviceKey);

    await expect(getDeviceKey("legacy-unsupported-user")).resolves.toEqual(legacyDeviceKey);
    expect(localSecretState.store.has("device-key:legacy-unsupported-user")).toBe(false);
    await expect(readLegacyDeviceKeyRecord("legacy-unsupported-user")).resolves.toEqual(
      expect.objectContaining({ userId: "legacy-unsupported-user" }),
    );
  });

  it("exports and imports device keys with versioned transfer encryption", async () => {
    const original = new Uint8Array(32);
    for (let index = 0; index < original.length; index += 1) {
      original[index] = index + 1;
    }

    await storeDeviceKey("user-1", original);
    const transferData = await exportDeviceKeyForTransfer("user-1", "random-transfer-secret-123");

    expect(transferData).toEqual(expect.stringMatching(/^sv-dk-transfer-v2:/));

    await deleteDeviceKey("user-1");
    await expect(importDeviceKeyFromTransfer("user-1", transferData!, "random-transfer-secret-123")).resolves.toBe(true);
    await expect(getDeviceKey("user-1")).resolves.toEqual(original);
  });

  it("rejects short transfer secrets and legacy raw transfer blobs", async () => {
    const original = new Uint8Array(32).fill(5);
    await storeDeviceKey("user-1", original);

    await expect(exportDeviceKeyForTransfer(
      "user-1",
      "x".repeat(DEVICE_KEY_TRANSFER_SECRET_MIN_LENGTH - 1),
    )).resolves.toBeNull();
    await expect(importDeviceKeyFromTransfer("user-1", "not-a-v2-envelope", "random-transfer-secret-123")).resolves.toBe(false);
  });

  it("rejects import when the transfer secret is wrong", async () => {
    const original = new Uint8Array(32).fill(5);
    await storeDeviceKey("user-1", original);

    const transferData = await exportDeviceKeyForTransfer("user-1", "random-transfer-secret-123");
    await deleteDeviceKey("user-1");

    await expect(importDeviceKeyFromTransfer("user-1", transferData!, "different-transfer-secret-456")).resolves.toBe(false);
    await expect(getDeviceKey("user-1")).resolves.toBeNull();
  });

  it("does not overwrite an existing device key during import", async () => {
    const existing = new Uint8Array(32).fill(8);
    const imported = new Uint8Array(32).fill(9);

    await storeDeviceKey("source-user", imported);
    const transferData = await exportDeviceKeyForTransfer("source-user", "random-transfer-secret-123");
    await storeDeviceKey("user-1", existing);

    await expect(importDeviceKeyFromTransfer("user-1", transferData!, "random-transfer-secret-123")).resolves.toBe(false);
    await expect(getDeviceKey("user-1")).resolves.toEqual(existing);
  });

  it("rejects downgraded or extreme transfer KDF parameters without storing a key", async () => {
    const original = new Uint8Array(32).fill(5);
    await storeDeviceKey("source-user", original);
    const transferData = await exportDeviceKeyForTransfer("source-user", "random-transfer-secret-123");

    const downgraded = decodeTransferEnvelope(transferData!);
    downgraded.memory = 1024;
    await expect(
      importDeviceKeyFromTransfer("target-user", encodeTransferEnvelope(downgraded), "random-transfer-secret-123"),
    ).resolves.toBe(false);

    const extreme = decodeTransferEnvelope(transferData!);
    extreme.memory = Number.MAX_SAFE_INTEGER;
    await expect(
      importDeviceKeyFromTransfer("target-user", encodeTransferEnvelope(extreme), "random-transfer-secret-123"),
    ).resolves.toBe(false);

    await expect(getDeviceKey("target-user")).resolves.toBeNull();
  });

  it("rejects malformed transfer data without overwriting an existing key", async () => {
    const existing = new Uint8Array(32).fill(8);
    await storeDeviceKey("user-1", existing);

    await expect(importDeviceKeyFromTransfer(
      "user-1",
      `${TRANSFER_PREFIX}not-base64-json`,
      "random-transfer-secret-123",
    )).resolves.toBe(false);
    await expect(getDeviceKey("user-1")).resolves.toEqual(existing);
  });
});
