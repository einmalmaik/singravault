import {
  createDeviceKeyInvalidError,
  createDeviceKeyMissingError,
  createUserKeyMigrationRequiredError,
  normalizeVaultProtectionMode,
  requiresDeviceKey,
} from "@/services/deviceKeyProtectionPolicy";

describe("deviceKeyProtectionPolicy", () => {
  it("normalizes only supported server protection modes", () => {
    expect(normalizeVaultProtectionMode("device_key_required")).toBe("device_key_required");
    expect(normalizeVaultProtectionMode("master_only")).toBe("master_only");
    expect(normalizeVaultProtectionMode(null)).toBe("master_only");
    expect(normalizeVaultProtectionMode("device-key-required")).toBe("master_only");
  });

  it("requires a Device Key only for device_key_required vaults", () => {
    expect(requiresDeviceKey("device_key_required")).toBe(true);
    expect(requiresDeviceKey("master_only")).toBe(false);
  });

  it("returns stable unlock error codes without secret material", () => {
    expect(createDeviceKeyMissingError().code).toBe("DEVICE_KEY_REQUIRED_BUT_MISSING");
    const invalid = createDeviceKeyInvalidError();
    expect(invalid.code).toBe("DEVICE_KEY_REQUIRED_BUT_INVALID");
    expect(invalid.message).not.toMatch(/device-key:|SINGRA_DEVICE_KEY|sv-dk-transfer/i);
  });

  it("fails closed when Device Key enablement is requested before UserKey migration", () => {
    const error = createUserKeyMigrationRequiredError();
    expect(error.code).toBe("USER_KEY_MIGRATION_REQUIRED");
    expect(error.message).toContain("UserKey wrapper");
    expect(error.message).not.toMatch(/device-key:|SINGRA_DEVICE_KEY|sv-dk-transfer|master password/i);
  });
});
