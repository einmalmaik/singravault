import { afterEach, describe, expect, it } from "vitest";
import { createAuthStorage, isPkceVerifierStorageKey } from "./authStorage";

describe("authStorage", () => {
  afterEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it("keeps normal auth session data in memory only", () => {
    const storage = createAuthStorage();
    const sessionKey = "sb-project-auth-token";

    storage.setItem(sessionKey, "session-json");

    expect(storage.getItem(sessionKey)).toBe("session-json");
    expect(window.sessionStorage.getItem(sessionKey)).toBeNull();
    expect(window.localStorage.getItem(sessionKey)).toBeNull();
  });

  it("returns empty memory values without falling through to session storage", () => {
    const storage = createAuthStorage();
    const sessionKey = "sb-project-auth-token";

    storage.setItem(sessionKey, "");

    expect(storage.getItem(sessionKey)).toBe("");
  });

  it("persists only the PKCE verifier across storage instances", () => {
    const verifierKey = "sb-project-auth-token-code-verifier";

    createAuthStorage().setItem(verifierKey, "verifier");

    expect(window.sessionStorage.getItem(verifierKey)).toBe("verifier");
    expect(window.localStorage.getItem(verifierKey)).toBe("verifier");
    expect(createAuthStorage().getItem(verifierKey)).toBe("verifier");
  });

  it("restores the PKCE verifier from local storage when session storage is gone", () => {
    const verifierKey = "sb-project-auth-token-code-verifier";

    createAuthStorage().setItem(verifierKey, "verifier");
    window.sessionStorage.clear();

    expect(createAuthStorage().getItem(verifierKey)).toBe("verifier");
  });

  it("removes PKCE verifier data from memory and session storage", () => {
    const storage = createAuthStorage();
    const verifierKey = "sb-project-auth-token-code-verifier";

    storage.setItem(verifierKey, "verifier");
    storage.removeItem(verifierKey);

    expect(storage.getItem(verifierKey)).toBeNull();
    expect(window.sessionStorage.getItem(verifierKey)).toBeNull();
    expect(window.localStorage.getItem(verifierKey)).toBeNull();
  });

  it("detects Supabase PKCE verifier keys", () => {
    expect(isPkceVerifierStorageKey("sb-project-auth-token-code-verifier")).toBe(true);
    expect(isPkceVerifierStorageKey("sb-project-auth-token")).toBe(false);
  });
});
