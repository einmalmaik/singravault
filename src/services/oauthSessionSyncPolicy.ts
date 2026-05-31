// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export interface OAuthSessionSyncPolicyInput {
  usesCookieSession: boolean;
  isDesktopRuntime: boolean;
}

export interface OAuthSessionSyncPolicy {
  shouldSync: boolean;
  skipCookie: boolean;
  credentials: RequestCredentials;
}

export function resolveOAuthSessionSyncPolicy(
  input: OAuthSessionSyncPolicyInput,
): OAuthSessionSyncPolicy {
  return {
    shouldSync: input.usesCookieSession || input.isDesktopRuntime,
    skipCookie: !input.usesCookieSession,
    credentials: input.usesCookieSession ? "include" : "omit",
  };
}
