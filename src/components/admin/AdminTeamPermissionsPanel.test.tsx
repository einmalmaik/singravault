// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("AdminTeamPermissionsPanel early return", () => {
    it("bypasses early return if canManageSubscriptions is true", () => {
        const source = readFileSync("src/components/admin/AdminTeamPermissionsPanel.tsx", "utf-8");

        // Match the new early return logic
        const hasAnyAccessMatch = source.match(/const hasAnyAccess = canReadRoles \|\| canReadPermissions \|\| canManageSubscriptions;/g);
        const earlyReturnMatch = source.match(/if \(!hasAnyAccess\) \{/g);

        expect(hasAnyAccessMatch).toBeTruthy();
        expect(earlyReturnMatch).toBeTruthy();
    });
});
