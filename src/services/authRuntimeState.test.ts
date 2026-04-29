import { describe, expect, it } from "vitest";

import { deriveAuthRuntimeState, type AuthRuntimeStateInput } from "./authRuntimeState";

const base: AuthRuntimeStateInput = {
  authReady: true,
  authLoading: false,
  hasUser: true,
  vaultLoading: false,
  vaultUnlocked: false,
  requiresTwoFactor: false,
  requiresDeviceKey: false,
  hasError: false,
};

describe("deriveAuthRuntimeState", () => {
  it("separates anonymous, locked and unlocked states", () => {
    expect(deriveAuthRuntimeState({ ...base, hasUser: false })).toBe("anonymous");
    expect(deriveAuthRuntimeState(base)).toBe("vault_locked");
    expect(deriveAuthRuntimeState({ ...base, vaultUnlocking: true })).toBe("vault_unlocking");
    expect(deriveAuthRuntimeState({ ...base, vaultUnlocked: true })).toBe("vault_unlocked");
  });

  it("keeps auth initialization distinct from vault lock", () => {
    expect(deriveAuthRuntimeState({ ...base, authReady: false })).toBe("initializing");
    expect(deriveAuthRuntimeState({ ...base, authLoading: true })).toBe("initializing");
    expect(deriveAuthRuntimeState({ ...base, vaultLoading: true })).toBe("initializing");
  });

  it("does not conflate Device Key and 2FA requirements", () => {
    expect(deriveAuthRuntimeState({ ...base, requiresDeviceKey: true })).toBe("requires_device_key");
    expect(deriveAuthRuntimeState({ ...base, requiresTwoFactor: true })).toBe("requires_2fa");
    expect(deriveAuthRuntimeState({
      ...base,
      requiresDeviceKey: true,
      requiresTwoFactor: true,
    })).toBe("requires_device_key");
  });

  it("keeps quarantine and integrity blocks separate from auth failures", () => {
    expect(deriveAuthRuntimeState({ ...base, hasItemQuarantine: true })).toBe("item_quarantine");
    expect(deriveAuthRuntimeState({ ...base, integrityBlocked: true })).toBe("integrity_blocked");
  });

  it("prioritizes explicit errors", () => {
    expect(deriveAuthRuntimeState({ ...base, hasError: true })).toBe("error");
  });
});
