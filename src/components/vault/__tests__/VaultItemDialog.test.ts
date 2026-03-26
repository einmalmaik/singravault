// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Unit tests for VaultItemDialog create-mode configuration helpers.
 */

import { describe, expect, it } from "vitest";

import {
  getAllowedCreateTypes,
  resolveInitialCreateType,
} from "../vaultItemDialogConfig";

describe("vaultItemDialogConfig", () => {
  it("filters create tabs to the explicitly allowed types", () => {
    expect(getAllowedCreateTypes(["password", "note"])).toEqual(["password", "note"]);
    expect(getAllowedCreateTypes(["totp"])).toEqual(["totp"]);
  });

  it("recomputes the configured initial type when the dialog reopens", () => {
    const allowedTypes = getAllowedCreateTypes(["password", "note", "totp"]);

    expect(resolveInitialCreateType("totp", allowedTypes, true)).toBe("totp");
    expect(resolveInitialCreateType("password", allowedTypes, true)).toBe("password");
    expect(resolveInitialCreateType("totp", allowedTypes, false)).toBe("password");
  });
});
