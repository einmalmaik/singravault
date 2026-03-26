// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Source-guard tests for VaultItemDialog create restrictions.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

describe("VaultItemDialog source guards", () => {
  it("supports restricting create mode to explicit item types", () => {
    const source = readFileSync("src/components/vault/VaultItemDialog.tsx", "utf-8");

    expect(source).toContain("allowedTypes?: VaultItemType[];");
    expect(source).toContain("const createTypeOptions = getAllowedCreateTypes(allowedTypes);");
    expect(source).toContain("!isEditing && createTypeOptions.length > 1");
    expect(source).toContain("createTypeOptions.includes('totp')");
  });

  it("recomputes the initial create type when the dialog reopens", () => {
    const source = readFileSync("src/components/vault/VaultItemDialog.tsx", "utf-8");

    expect(source).toContain("const resolvedInitialItemType = resolveInitialCreateType(initialType, createTypeOptions, canUseTotp);");
    expect(source).toContain("setItemType(resolvedInitialItemType);");
    expect(source).not.toContain("setItemType('password');");
  });
});
