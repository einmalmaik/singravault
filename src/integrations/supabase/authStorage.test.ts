import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearDesktopPersistedSessionTokens,
  createAuthStorage,
  getDesktopSessionStorageKey,
  isPkceVerifierStorageKey,
  purgeLegacyDesktopAuthTokens,
  readDesktopPersistedSessionTokens,
} from "./authStorage";

const invokeMock = vi.hoisted(() => vi.fn());
const runtimeState = vi.hoisted(() => ({
  isTauri: false,
}));

vi.mock("@/platform/tauriInvoke", () => ({
  getTauriInvoke: vi.fn(async () => invokeMock),
}));

vi.mock("@/platform/runtime", () => ({
  isTauriRuntime: () => runtimeState.isTauri,
}));

describe("authStorage", () => {
  afterEach(() => {
    invokeMock.mockReset();
    runtimeState.isTauri = false;
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it("keeps normal auth session data in memory only", async () => {
    const storage = createAuthStorage();
    const sessionKey = "sb-project-auth-token";

    await storage.setItem(sessionKey, "session-json");

    await expect(storage.getItem(sessionKey)).resolves.toBe("session-json");
    expect(window.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(window.localStorage.getItem(sessionKey)).toBeNull();
  });

  it("returns empty memory values without falling through to session storage", async () => {
    const storage = createAuthStorage();
    const sessionKey = "sb-project-auth-token";

    await storage.setItem(sessionKey, "");

    await expect(storage.getItem(sessionKey)).resolves.toBe("");
  });

  it("keeps desktop auth session data in memory only and not in localStorage", async () => {
    runtimeState.isTauri = true;
    const sessionKey = "sb-project-auth-token";

    await createAuthStorage().setItem(sessionKey, "session-json");

    expect(window.localStorage.getItem(sessionKey)).toBeNull();
    await expect(createAuthStorage().getItem(sessionKey)).resolves.toBeNull();
  });

  it("persists only the PKCE verifier across storage instances", async () => {
    const verifierKey = "sb-project-auth-token-code-verifier";

    await createAuthStorage().setItem(verifierKey, "verifier");

    expect(window.sessionStorage.getItem(verifierKey)).toBe("verifier");
    expect(window.localStorage.getItem(verifierKey)).toBe("verifier");
    await expect(createAuthStorage().getItem(verifierKey)).resolves.toBe("verifier");
  });

  it("restores the PKCE verifier from local storage when session storage is gone", async () => {
    const verifierKey = "sb-project-auth-token-code-verifier";

    await createAuthStorage().setItem(verifierKey, "verifier");
    window.sessionStorage.clear();

    await expect(createAuthStorage().getItem(verifierKey)).resolves.toBe("verifier");
  });

  it("restores the PKCE verifier from native storage when Web storage is gone", async () => {
    const verifierKey = "sb-project-auth-token-code-verifier";
    const nativeStore = new Map<string, string>();
    invokeMock.mockImplementation(async (command: string, args: Record<string, unknown> = {}) => {
      if (command === "save_pkce_verifier") {
        nativeStore.set(String(args.key), String(args.verifier));
        return null;
      }

      if (command === "load_pkce_verifier") {
        return nativeStore.get(String(args.key)) ?? null;
      }

      if (command === "clear_pkce_verifier") {
        nativeStore.delete(String(args.key));
        return null;
      }

      return null;
    });

    await createAuthStorage().setItem(verifierKey, "verifier");
    window.sessionStorage.clear();
    window.localStorage.clear();

    await expect(createAuthStorage().getItem(verifierKey)).resolves.toBe("verifier");
  });

  it("removes PKCE verifier data from memory and session storage", async () => {
    const storage = createAuthStorage();
    const verifierKey = "sb-project-auth-token-code-verifier";

    await storage.setItem(verifierKey, "verifier");
    await storage.removeItem(verifierKey);

    await expect(storage.getItem(verifierKey)).resolves.toBeNull();
    expect(window.sessionStorage.getItem(verifierKey)).toBeNull();
    expect(window.localStorage.getItem(verifierKey)).toBeNull();
  });

  it("detects Supabase PKCE verifier keys", () => {
    expect(isPkceVerifierStorageKey("sb-project-auth-token-code-verifier")).toBe(true);
    expect(isPkceVerifierStorageKey("sb-project-auth-token")).toBe(false);
  });

  it("derives the desktop Supabase session key from the project URL", () => {
    expect(getDesktopSessionStorageKey("https://lcrtadxlojaucwapgzmy.supabase.co"))
      .toBe("sb-lcrtadxlojaucwapgzmy-auth-token");
    expect(getDesktopSessionStorageKey("not-a-url")).toBeNull();
  });

  it("deletes and ignores legacy desktop session snapshots from localStorage", () => {
    runtimeState.isTauri = true;
    const supabaseUrl = "https://lcrtadxlojaucwapgzmy.supabase.co";
    const sessionKey = "sb-lcrtadxlojaucwapgzmy-auth-token";
    localStorage.setItem(
      sessionKey,
      JSON.stringify({
        access_token: "desktop-access-token",
        refresh_token: "desktop-refresh-token",
      }),
    );

    expect(readDesktopPersistedSessionTokens(supabaseUrl)).toBeNull();
    expect(localStorage.getItem(sessionKey)).toBeNull();
  });

  it("purges all legacy Supabase auth-token keys without touching PKCE verifier keys", () => {
    runtimeState.isTauri = true;
    localStorage.setItem("sb-lcrtadxlojaucwapgzmy-auth-token", "session-json");
    localStorage.setItem("sb-otherproject-auth-token", "session-json");
    localStorage.setItem("sb-lcrtadxlojaucwapgzmy-auth-token-code-verifier", "verifier");

    expect(purgeLegacyDesktopAuthTokens()).toBe(2);

    expect(localStorage.getItem("sb-lcrtadxlojaucwapgzmy-auth-token")).toBeNull();
    expect(localStorage.getItem("sb-otherproject-auth-token")).toBeNull();
    expect(localStorage.getItem("sb-lcrtadxlojaucwapgzmy-auth-token-code-verifier")).toBe("verifier");
  });

  it("can explicitly clear a persisted desktop session snapshot", () => {
    runtimeState.isTauri = true;
    const supabaseUrl = "https://lcrtadxlojaucwapgzmy.supabase.co";
    const sessionKey = "sb-lcrtadxlojaucwapgzmy-auth-token";
    localStorage.setItem(sessionKey, "session-json");

    clearDesktopPersistedSessionTokens(supabaseUrl);

    expect(localStorage.getItem(sessionKey)).toBeNull();
  });
});
