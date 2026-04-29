// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export interface E2ETestModeConfig {
  enabled: boolean;
  email: string | null;
  passwordConfigured: boolean;
  masterPasswordConfigured: boolean;
}

function readBooleanEnv(value: unknown): boolean {
  return String(value ?? "").trim().toLowerCase() === "true";
}

function readStringEnv(value: unknown): string | null {
  const normalized = String(value ?? "").trim();
  return normalized.length > 0 ? normalized : null;
}

export function isE2ETestModeEnabled(): boolean {
  return readBooleanEnv(import.meta.env.VITE_E2E_TEST_MODE);
}

export function assertNoUnsafeE2ETestMode(): void {
  if (isUnsafeE2ETestMode(import.meta.env.PROD, import.meta.env.VITE_E2E_TEST_MODE)) {
    throw new Error("VITE_E2E_TEST_MODE must not be enabled in production builds.");
  }
}

export function isUnsafeE2ETestMode(isProduction: boolean, value: unknown): boolean {
  return isProduction && readBooleanEnv(value);
}

export function getE2ETestModeConfig(): E2ETestModeConfig {
  assertNoUnsafeE2ETestMode();

  return {
    enabled: isE2ETestModeEnabled(),
    email: readStringEnv(import.meta.env.VITE_E2E_TEST_EMAIL),
    passwordConfigured: readStringEnv(import.meta.env.VITE_E2E_TEST_PASSWORD) !== null,
    masterPasswordConfigured: readStringEnv(import.meta.env.VITE_E2E_TEST_MASTER_PASSWORD) !== null,
  };
}
