// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Tests for postAuthRedirectService.
 */

import { describe, expect, it } from "vitest";

import { resolvePostAuthRedirectPath } from "@/services/postAuthRedirectService";

describe("resolvePostAuthRedirectPath", () => {
  it("always returns landing page for protected-route redirects", () => {
    expect(resolvePostAuthRedirectPath("/vault", { from: { pathname: "/vault" } })).toBe("/");
  });

  it("always returns landing page for auth-like redirect params", () => {
    expect(resolvePostAuthRedirectPath("/authenticator", null)).toBe("/");
    expect(resolvePostAuthRedirectPath("/auth", null)).toBe("/");
  });

  it("always returns landing page without redirect input", () => {
    expect(resolvePostAuthRedirectPath(null, undefined)).toBe("/");
  });
});

