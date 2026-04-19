import { describe, expect, it } from "vitest";
import {
  buildTauriOAuthCallbackUrl,
  hasOAuthCallbackPayload,
  parseOAuthCallbackPayload,
} from "./tauriOAuthCallback";

describe("tauriOAuthCallback", () => {
  it("moves implicit hash tokens into the app callback query", () => {
    const appUrl = buildTauriOAuthCallbackUrl(
      "https://singravault.mauntingstudios.de/auth?source=tauri#access_token=access&refresh_token=refresh&expires_in=3600",
    );

    expect(appUrl).toBe(
      "singravault://auth/callback?source=tauri&access_token=access&refresh_token=refresh&expires_in=3600",
    );
  });

  it("preserves PKCE codes for exchange inside the Tauri client", () => {
    const appUrl = buildTauriOAuthCallbackUrl(
      "https://singravault.mauntingstudios.de/auth?source=tauri&code=oauth-code",
    );

    expect(appUrl).toBe("singravault://auth/callback?source=tauri&code=oauth-code");
  });

  it("does not build an app callback for normal web auth callbacks", () => {
    const appUrl = buildTauriOAuthCallbackUrl(
      "https://singravault.mauntingstudios.de/auth#access_token=access&refresh_token=refresh",
    );

    expect(appUrl).toBeNull();
  });

  it("parses session tokens from custom-scheme query params", () => {
    const payload = parseOAuthCallbackPayload(
      "singravault://auth/callback?access_token=access&refresh_token=refresh",
    );

    expect(payload?.tokens).toEqual({
      access_token: "access",
      refresh_token: "refresh",
    });
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
    expect(hasOAuthCallbackPayload("singravault://auth/callback?source=tauri")).toBe(false);
  });
});
