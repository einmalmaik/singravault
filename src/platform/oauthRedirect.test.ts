import { describe, expect, it, vi } from "vitest";
import { TAURI_OAUTH_CALLBACK_URL } from "./tauriOAuthCallback";

const runtime = vi.hoisted(() => ({ isTauri: false }));

vi.mock("./runtime", () => ({
  isTauriRuntime: () => runtime.isTauri,
}));

import { getOAuthRedirectUrl } from "./oauthRedirect";

describe("getOAuthRedirectUrl", () => {
  it("uses the direct desktop deep link inside Tauri", () => {
    runtime.isTauri = true;

    expect(getOAuthRedirectUrl()).toBe(TAURI_OAUTH_CALLBACK_URL);
  });

  it("uses the web auth route outside Tauri", () => {
    runtime.isTauri = false;

    expect(getOAuthRedirectUrl()).toBe(`${window.location.origin}/auth`);
  });
});
