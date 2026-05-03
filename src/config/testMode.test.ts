import { describe, expect, it, vi, afterEach } from "vitest";

import { getE2ETestModeConfig, isUnsafeE2ETestMode } from "./testMode";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("testMode", () => {
  it("keeps E2E mode disabled by default", () => {
    vi.stubEnv("VITE_DEV_TEST_ACCOUNT_UI", "false");

    expect(getE2ETestModeConfig()).toEqual({
      uiEnabled: false,
      email: null,
    });
  });

  it("exposes only non-sensitive dev test account UI metadata", () => {
    vi.stubEnv("VITE_DEV_TEST_ACCOUNT_UI", "true");
    vi.stubEnv("VITE_DEV_TEST_EMAIL", "test@example.local");

    expect(getE2ETestModeConfig()).toEqual({
      uiEnabled: true,
      email: "test@example.local",
    });
  });

  it("detects unsafe production test mode", () => {
    expect(isUnsafeE2ETestMode(true, "true")).toBe(true);
    expect(isUnsafeE2ETestMode(true, "false")).toBe(false);
    expect(isUnsafeE2ETestMode(false, "true")).toBe(false);
  });
});
