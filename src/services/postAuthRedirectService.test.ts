// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for postAuthRedirectService.
 */

import { describe, expect, it } from "vitest";

import { resolvePostAuthRedirectPath } from "@/services/postAuthRedirectService";

describe("resolvePostAuthRedirectPath", () => {
  it("prefers an explicit safe redirect target", () => {
    expect(resolvePostAuthRedirectPath("/settings", { from: { pathname: "/vault" } })).toBe("/settings");
  });

  it("falls back to the guarded route when no query redirect is present", () => {
    expect(
      resolvePostAuthRedirectPath(null, { from: { pathname: "/vault/settings", search: "?tab=security", hash: "#mfa" } }),
    ).toBe("/vault/settings?tab=security#mfa");
  });

  it("rejects auth routes and external-looking redirects", () => {
    expect(resolvePostAuthRedirectPath("/auth", { from: { pathname: "/auth" } })).toBe("/vault");
    expect(resolvePostAuthRedirectPath("//evil.example", undefined)).toBe("/vault");
    expect(resolvePostAuthRedirectPath("https://evil.example", undefined)).toBe("/vault");
  });

  it("defaults to the vault without redirect input", () => {
    expect(resolvePostAuthRedirectPath(null, undefined)).toBe("/vault");
  });
});

