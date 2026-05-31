// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";

import { resolveOAuthSessionSyncPolicy } from "./oauthSessionSyncPolicy";

describe("resolveOAuthSessionSyncPolicy", () => {
  it("syncs web OAuth callbacks through the BFF cookie session", () => {
    expect(resolveOAuthSessionSyncPolicy({
      usesCookieSession: true,
      isDesktopRuntime: false,
    })).toEqual({
      shouldSync: true,
      skipCookie: false,
      credentials: "include",
    });
  });

  it("syncs Tauri OAuth callbacks without writing a BFF cookie", () => {
    expect(resolveOAuthSessionSyncPolicy({
      usesCookieSession: false,
      isDesktopRuntime: true,
    })).toEqual({
      shouldSync: true,
      skipCookie: true,
      credentials: "omit",
    });
  });

  it("does not sync iframe callbacks that cannot use either desktop or BFF session storage", () => {
    expect(resolveOAuthSessionSyncPolicy({
      usesCookieSession: false,
      isDesktopRuntime: false,
    })).toEqual({
      shouldSync: false,
      skipCookie: true,
      credentials: "omit",
    });
  });
});
