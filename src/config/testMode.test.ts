import { describe, expect, it, vi, afterEach } from "vitest";

import { getE2ETestModeConfig, isUnsafeE2ETestMode } from "./testMode";

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("testMode", () => {
  it("keeps E2E mode disabled by default", () => {
    vi.stubEnv("VITE_E2E_TEST_MODE", "false");

    expect(getE2ETestModeConfig()).toEqual({
      enabled: false,
      email: null,
      passwordConfigured: false,
      masterPasswordConfigured: false,
    });
  });

  it("reports only whether test credentials are configured without exposing them", () => {
    vi.stubEnv("VITE_E2E_TEST_MODE", "true");
    vi.stubEnv("VITE_E2E_TEST_EMAIL", "test@example.local");
    vi.stubEnv("VITE_E2E_TEST_PASSWORD", "not-logged");
    vi.stubEnv("VITE_E2E_TEST_MASTER_PASSWORD", "not-logged-either");

    expect(getE2ETestModeConfig()).toEqual({
      enabled: true,
      email: "test@example.local",
      passwordConfigured: true,
      masterPasswordConfigured: true,
    });
  });

  it("detects unsafe production test mode", () => {
    expect(isUnsafeE2ETestMode(true, "true")).toBe(true);
    expect(isUnsafeE2ETestMode(true, "false")).toBe(false);
    expect(isUnsafeE2ETestMode(false, "true")).toBe(false);
  });
});
