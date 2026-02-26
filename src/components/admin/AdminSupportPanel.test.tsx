// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("AdminSupportPanel race guards", () => {
  it("contains async mutation guards for reply and status updates", () => {
    const source = readFileSync("src/components/admin/AdminSupportPanel.tsx", "utf-8");

    const activeTicketIdMatches = source.match(/const activeTicketId = selectedTicketId;/g) || [];
    const guardCommentMatches = source.match(
      /Guard: skip refresh if user switched tickets during async mutation/g,
    ) || [];
    const guardConditionMatches = source.match(
      /activeTicketId === selectedTicketIdRef\.current/g,
    ) || [];

    expect(activeTicketIdMatches).toHaveLength(2);
    expect(guardCommentMatches).toHaveLength(2);
    expect(guardConditionMatches).toHaveLength(2);
  });
});
