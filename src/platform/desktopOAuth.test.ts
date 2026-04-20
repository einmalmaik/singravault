import { afterEach, describe, expect, it, vi } from "vitest";
import { createDesktopOAuthUrl, exchangeDesktopOAuthCode } from "./desktopOAuth";

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

  it("creates a Supabase provider URL with a web bridge callback and PKCE challenge", async () => {
    const url = new URL(await createDesktopOAuthUrl("google"));
    const redirectTo = new URL(url.searchParams.get("redirect_to") ?? "");

    expect(url.origin).toBe("https://lcrtadxlojaucwapgzmy.supabase.co");
    expect(url.pathname).toBe("/auth/v1/authorize");
    expect(url.searchParams.get("provider")).toBe("google");
    expect(redirectTo.pathname).toBe("/auth");
    expect(redirectTo.searchParams.get("source")).toBe("tauri");
    expect(url.searchParams.get("code_challenge_method")).toBe("s256");
    expect(url.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(url.searchParams.has("state")).toBe(false);
  });

  it("exchanges a callback code with the active verifier", async () => {
    await createDesktopOAuthUrl("discord");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "access-token",
        refresh_token: "refresh-token",
        token_type: "bearer",
        expires_in: 3600,
      })),
    );

    await expect(exchangeDesktopOAuthCode("auth-code")).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });

    const [, requestInit] = fetchMock.mock.calls[0];
    const body = JSON.parse(String(requestInit?.body)) as Record<string, string>;
    expect(fetchMock.mock.calls[0][0]).toBe("https://lcrtadxlojaucwapgzmy.supabase.co/auth/v1/token?grant_type=pkce");
    expect(body.auth_code).toBe("auth-code");
    expect(body.code_verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(window.localStorage.getItem("singra-desktop-oauth:active")).toBeNull();
  });

  it("does not require OAuth state because Supabase owns provider state", async () => {
    await createDesktopOAuthUrl("github");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        access_token: "access-token",
        refresh_token: "refresh-token",
      })),
    );

    await expect(exchangeDesktopOAuthCode("auth-code")).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });
  });

  it("deduplicates concurrent exchanges for the same auth code", async () => {
    await createDesktopOAuthUrl("google");
    let resolveResponse!: (value: Response) => void;
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      () => new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      }),
    );

    const first = exchangeDesktopOAuthCode("shared-code");
    const second = exchangeDesktopOAuthCode("shared-code");
    await Promise.resolve();
    resolveResponse(new Response(JSON.stringify({
      access_token: "access-token",
      refresh_token: "refresh-token",
    }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));

    await expect(first).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });
    await expect(second).resolves.toEqual({
      access_token: "access-token",
      refresh_token: "refresh-token",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the verifier for retryable rate limits", async () => {
    await createDesktopOAuthUrl("discord");
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({
        error: "rate_limit",
        error_description: "Request rate limit reached",
      }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(exchangeDesktopOAuthCode("auth-code")).rejects.toThrow("Request rate limit reached");
    expect(window.localStorage.getItem("singra-desktop-oauth:active")).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("fails before token exchange when no verifier exists", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    await expect(exchangeDesktopOAuthCode("auth-code")).rejects.toThrow("verifier is missing");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
