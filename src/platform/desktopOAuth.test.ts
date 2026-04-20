import { afterEach, describe, expect, it, vi } from "vitest";
import { createDesktopOAuthUrl, exchangeDesktopOAuthCode } from "./desktopOAuth";
import { TAURI_OAUTH_CALLBACK_URL } from "./tauriOAuthCallback";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@/platform/tauriInvoke", () => ({
  getTauriInvoke: vi.fn(async () => invokeMock),
}));

describe("desktopOAuth", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    invokeMock.mockReset();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it("creates a Supabase provider URL with explicit PKCE state", async () => {
    const url = new URL(await createDesktopOAuthUrl("google"));

    expect(url.origin).toBe("https://lcrtadxlojaucwapgzmy.supabase.co");
    expect(url.pathname).toBe("/auth/v1/authorize");
    expect(url.searchParams.get("provider")).toBe("google");
    expect(url.searchParams.get("redirect_to")).toBe(TAURI_OAUTH_CALLBACK_URL);
    expect(url.searchParams.get("code_challenge_method")).toBe("s256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(url.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("exchanges a callback code with the verifier stored for state", async () => {
    const url = new URL(await createDesktopOAuthUrl("discord"));
    const state = url.searchParams.get("state");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "access-token",
        refresh_token: "refresh-token",
        token_type: "bearer",
        expires_in: 3600,
      })),
    );

    await expect(exchangeDesktopOAuthCode("auth-code", state)).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });

    const [, requestInit] = fetchMock.mock.calls[0];
    const body = JSON.parse(String(requestInit?.body)) as Record<string, string>;
    expect(fetchMock.mock.calls[0][0]).toBe("https://lcrtadxlojaucwapgzmy.supabase.co/auth/v1/token?grant_type=pkce");
    expect(body.auth_code).toBe("auth-code");
    expect(body.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(window.localStorage.getItem(`singra-desktop-oauth:${state}`)).toBeNull();
    expect(window.localStorage.getItem("singra-desktop-oauth:active")).toBeNull();
  });

  it("falls back to the active verifier when Supabase does not return state", async () => {
    await createDesktopOAuthUrl("github");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "access-token",
        refresh_token: "refresh-token",
      })),
    );

    await expect(exchangeDesktopOAuthCode("auth-code", null)).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });
  });

  it("fails before token exchange when callback state has no stored verifier", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    await expect(exchangeDesktopOAuthCode("auth-code", "missing-state")).rejects.toThrow("verifier is missing");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
