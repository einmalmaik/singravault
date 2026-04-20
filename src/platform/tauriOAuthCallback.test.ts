import { describe, expect, it } from "vitest";
import {
  createTauriOAuthCallbackUrl,
  hasOAuthCallbackPayload,
  isTauriOAuthCallbackUrl,
  normalizeOAuthCallbackInput,
  parseOAuthCallbackPayload,
} from "./tauriOAuthCallback";

describe("tauriOAuthCallback", () => {
  it("parses session tokens from custom-scheme query params", () => {
    const payload = parseOAuthCallbackPayload(
      "singravault://auth/callback?access_token=access&refresh_token=refresh",
    );

    expect(payload?.tokens).toEqual({
      access_token: "access",
      refresh_token: "refresh",
    });
  });

  it("parses session tokens from custom-scheme hash params", () => {
    const payload = parseOAuthCallbackPayload(
      "singravault://auth/callback#access_token=access&refresh_token=refresh",
    );

    expect(payload?.tokens).toEqual({
      access_token: "access",
      refresh_token: "refresh",
    });
  });

  it("parses same-origin web auth callbacks", () => {
    const payload = parseOAuthCallbackPayload(
      "https://singravault.mauntingstudios.de/auth#access_token=access&refresh_token=refresh",
      "https://singravault.mauntingstudios.de",
    );

    expect(payload?.tokens).toEqual({
      access_token: "access",
      refresh_token: "refresh",
    });
  });

  it("rejects unexpected callback locations", () => {
    expect(parseOAuthCallbackPayload("singravault://profile/callback?code=abc")).toBeNull();
    expect(
      parseOAuthCallbackPayload(
        "https://example.com/auth#access_token=access&refresh_token=refresh",
        "https://singravault.mauntingstudios.de",
      ),
    ).toBeNull();
  });

  it("detects desktop callback locations without requiring a payload", () => {
    expect(isTauriOAuthCallbackUrl("singravault://auth/callback")).toBe(true);
    expect(isTauriOAuthCallbackUrl("https://singravault.mauntingstudios.de/auth?code=abc")).toBe(false);
    expect(isTauriOAuthCallbackUrl("singravault://profile/callback?code=abc")).toBe(false);
  });

  it("parses PKCE code and OAuth errors", () => {
    expect(parseOAuthCallbackPayload("singravault://auth/callback?code=abc")?.code).toBe("abc");
    expect(
      parseOAuthCallbackPayload(
        "singravault://auth/callback?error=access_denied&error_description=Denied",
      )?.error,
    ).toEqual({
      error: "access_denied",
      errorCode: null,
      description: "Denied",
    });
  });

  it("detects auth payload in either search or hash", () => {
    expect(hasOAuthCallbackPayload("singravault://auth/callback?code=abc")).toBe(true);
    expect(hasOAuthCallbackPayload("singravault://auth/callback#access_token=a")).toBe(true);
    expect(hasOAuthCallbackPayload("singravault://auth/callback?state=opaque")).toBe(false);
  });

  it("normalizes manually pasted token fragments into app callbacks", () => {
    expect(normalizeOAuthCallbackInput("#access_token=access&refresh_token=refresh")).toBe(
      "singravault://auth/callback?access_token=access&refresh_token=refresh",
    );
    expect(normalizeOAuthCallbackInput("access_token=access&refresh_token=refresh")).toBe(
      "singravault://auth/callback?access_token=access&refresh_token=refresh",
    );
  });

  it("normalizes manually pasted web bridge callbacks into app callbacks", () => {
    expect(
      normalizeOAuthCallbackInput(
        "https://singravault.mauntingstudios.de/auth?source=tauri&code=abc",
        "https://singravault.mauntingstudios.de",
      ),
    ).toBe("singravault://auth/callback?code=abc");
  });

  it("omits bridge-only params when creating app callbacks", () => {
    const params = new URLSearchParams("source=tauri&code=abc");

    expect(createTauriOAuthCallbackUrl(params)).toBe("singravault://auth/callback?code=abc");
  });

  it("rejects manual input without an auth payload", () => {
    expect(normalizeOAuthCallbackInput("https://example.com/auth?state=opaque")).toBeNull();
  });
});
