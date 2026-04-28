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

const LOCAL_SECRET_DB_NAME = "singra-local-secrets";
const LOCAL_SECRET_STORE = "secrets";

function requestToPromise<T>(request: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error);
  });
}

async function openLocalSecretDb(): Promise<IDBDatabase> {
  const request = indexedDB.open(LOCAL_SECRET_DB_NAME, 1);
  return requestToPromise<IDBDatabase>(request);
}

async function writeRawSecretRecord(key: string, payload: string): Promise<void> {
  const db = await openLocalSecretDb();
  const transaction = db.transaction(LOCAL_SECRET_STORE, "readwrite");
  const store = transaction.objectStore(LOCAL_SECRET_STORE);
  await requestToPromise(store.put({
    key,
    payload,
    updatedAt: new Date().toISOString(),
  }));
}

async function readRawSecretRecord(key: string): Promise<unknown> {
  const db = await openLocalSecretDb();
  const transaction = db.transaction(LOCAL_SECRET_STORE, "readonly");
  const store = transaction.objectStore(LOCAL_SECRET_STORE);
  return requestToPromise(store.get(key));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }

  return btoa(binary);
}

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
    const key = "vault-integrity:00000000-0000-4000-8000-000000000001";
    runtimeState.isTauri = true;
    runtimeState.invoke.mockResolvedValueOnce(undefined);
    runtimeState.invoke.mockResolvedValueOnce("c2VjcmV0");
    runtimeState.invoke.mockResolvedValueOnce(undefined);

    const store = await import("./localSecretStore");

    await store.saveLocalSecretBytes(key, new Uint8Array([115, 101, 99, 114, 101, 116]));
    const loaded = await store.loadLocalSecretBytes(key);
    await store.removeLocalSecret(key);

    expect(Array.from(loaded ?? [])).toEqual([115, 101, 99, 114, 101, 116]);
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(1, "save_local_secret", {
      key,
      value: "c2VjcmV0",
    });
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(2, "load_local_secret", {
      key,
    });
    expect(runtimeState.invoke).toHaveBeenNthCalledWith(3, "clear_local_secret", {
      key,
    });
  });

  it("keeps browser secrets stored when decrypting them fails", async () => {
    const store = await import("./localSecretStore");
    const key = "device-key:corrupted";
    const corruptedPayload = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));

    await store.saveLocalSecretString(key, "payload-123");
    await writeRawSecretRecord(key, corruptedPayload);

    await expect(store.loadLocalSecretBytes(key)).resolves.toBeNull();
    await expect(readRawSecretRecord(key)).resolves.toEqual(
      expect.objectContaining({ key, payload: corruptedPayload }),
    );
  });
});
