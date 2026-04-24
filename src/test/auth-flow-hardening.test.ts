// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { checkAuthRateLimit } from "../../supabase/functions/_shared/authRateLimit";

interface MockAttempt {
  success: boolean;
  attempted_at: string;
  locked_until: string | null;
}

describe("auth flow hardening", () => {
  it("keeps recovery verification reset-scoped instead of issuing app sessions", () => {
    const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");
    const resetSource = readFileSync("supabase/functions/auth-reset-password/index.ts", "utf-8");
    const authPageSource = readFileSync("src/pages/Auth.tsx", "utf-8");
    const verifyRecoverSection = extractSection(
      authPageSource,
      "const handleVerifyRecover",
      "const handleUpdatePassword",
    );

    expect(recoverySource).toContain("password_reset_challenges");
    expect(recoverySource).toContain("resetToken");
    expect(recoverySource).not.toContain("authClient.auth.verifyOtp");
    expect(recoverySource).not.toContain("access_token");
    expect(recoverySource).not.toContain("refresh_token");
    expect(verifyRecoverSection).toContain("setPasswordResetToken(resetToken)");
    expect(verifyRecoverSection).not.toContain("applyAuthenticatedSession");
    expect(resetSource).toContain("resetToken");
    expect(resetSource).toContain("used_at");
    expect(resetSource).toContain("revoke_user_auth_sessions");
    expect(resetSource).toContain('throw new Error("Failed to revoke existing sessions after password reset")');
    expect(resetSource).toContain("sendPasswordResetNotification");
    expect(migrationSourceForSessions()).not.toContain("WHERE user_id = p_user_id::TEXT");
    expect(migrationSourceForSessions()).toContain("information_schema.columns");
  });

  it("enforces auth-specific server-side throttling in critical auth paths", () => {
    const helperSource = readFileSync("supabase/functions/_shared/authRateLimit.ts", "utf-8");
    const sessionSource = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");
    const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");
    const migrationSource = readFileSync("supabase/migrations/20260423210000_auth_flow_hardening.sql", "utf-8");
    const opaqueStartSection = extractSection(
      opaqueSource,
      "async function handleLoginStart",
      "async function handleLoginFinish",
    );

    for (const action of [
      "password_login",
      "recovery_verify",
      "totp_verify",
      "backup_code_verify",
      "opaque_login",
    ]) {
      expect(helperSource).toContain(action);
      expect(migrationSource).toContain(action);
    }

    expect(sessionSource).toContain('action: "password_login"');
    expect(sessionSource).not.toContain('action: "totp_verify"');
    expect(sessionSource).not.toContain('action: "backup_code_verify"');
    expect(opaqueSource).toContain('action: "opaque_login"');
    expect(opaqueSource).toContain('action: params.isBackupCode ? "backup_code_verify" : "totp_verify"');
    expect(opaqueSource).toContain("opaqueUnavailableResponse");
    expect(opaqueStartSection).toContain("opaqueUnavailableResponse(opaqueRateLimit, startTime, headers)");
    expect(opaqueStartSection).toContain('invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials")');
    expect(recoverySource).toContain('action: "recovery_verify"');
    expect(sessionSource).toContain("recordAuthRateLimitFailure");
    expect(opaqueSource).toContain("recordAuthRateLimitFailure");
    expect(recoverySource).toContain("recordAuthRateLimitFailure");
  });

  it("removes legacy app-password login as a client or server bypass", () => {
    const authPageSource = readFileSync("src/pages/Auth.tsx", "utf-8");
    const sessionSource = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");
    const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const registerSource = readFileSync("supabase/functions/auth-register/index.ts", "utf-8");
    const resetSource = readFileSync("supabase/functions/auth-reset-password/index.ts", "utf-8");
    const loadtestSource = readFileSync("loadtest/lib/supabase.js", "utf-8");

    expect(authPageSource).not.toContain("legacyLogin");
    expect(authPageSource).not.toContain("migrateToOpaque");
    expect(authPageSource).not.toContain("password: data.password");
    expect(authPageSource).toContain("verifyOpaqueSessionBinding");
    expect(sessionSource).toContain("LEGACY_PASSWORD_LOGIN_DISABLED");
    expect(sessionSource).not.toContain("signInWithPassword");
    expect(sessionSource).not.toContain("argon2Verify");
    expect(opaqueSource).not.toContain("useLegacy");
    expect(opaqueSource).toContain("disableGotruePasswordLogin");
    expect(registerSource).toContain("disableGotruePasswordLogin");
    expect(resetSource).toContain("disableGotruePasswordLogin");
    expect(registerSource).not.toContain("argon2id");
    expect(resetSource).toContain("OPAQUE password reset required");
    expect(resetSource).not.toContain("newPassword");
    expect(loadtestSource).not.toContain("grant_type=password");
  });

  it("keeps the OPAQUE identifier and server-key/session binding explicit", () => {
    const clientOpaqueSource = readFileSync("src/services/opaqueService.ts", "utf-8");
    const serverOpaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const migrationSource = readFileSync("supabase/migrations/20260424120000_enforce_opaque_password_auth.sql", "utf-8");

    expect(clientOpaqueSource).toContain("normalizeOpaqueIdentifier");
    expect(clientOpaqueSource).toContain("OPAQUE_KEY_STRETCHING");
    expect(clientOpaqueSource).toContain("'memory-constrained'");
    expect(clientOpaqueSource).toContain("assertServerStaticPublicKey");
    expect(clientOpaqueSource).toContain("verifyOpaqueSessionBinding");
    expect(serverOpaqueSource).toContain("opaque_identifier");
    expect(serverOpaqueSource).toContain("createOpaqueSessionBindingProof");
    expect(migrationSource).toContain("opaque_identifier");
    expect(migrationSource).toContain("opaque_registration_challenges");
    expect(migrationSource).toContain("opaque_password_reset_states");
    expect(migrationSource).toContain("disable_gotrue_password_login");
    expect(migrationSource).toContain("encrypted_password = NULL");
  });

  it("keeps long lockouts active after the short attempt window has elapsed", async () => {
    const now = Date.now();
    const activeLockoutOutsideRecoveryWindow: MockAttempt = {
      success: false,
      attempted_at: new Date(now - 20 * 60 * 1000).toISOString(),
      locked_until: new Date(now + 40 * 60 * 1000).toISOString(),
    };

    const state = await checkAuthRateLimit({
      supabaseAdmin: createRateLimitSupabaseMock({
        accountAttempts: [activeLockoutOutsideRecoveryWindow],
        ipAttempts: [],
      }),
      req: new Request("https://example.test/auth", {
        headers: { "CF-Connecting-IP": "203.0.113.20" },
      }),
      action: "recovery_verify",
      account: { kind: "email", value: "person@example.test" },
    });

    expect(state.allowed).toBe(false);
    expect(state.status).toBe(429);
    expect(state.retryAfterSeconds).toBeGreaterThan(0);
  });
});

function extractSection(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

function migrationSourceForSessions(): string {
  return readFileSync("supabase/migrations/20260423210000_auth_flow_hardening.sql", "utf-8");
}

function createRateLimitSupabaseMock({
  accountAttempts,
  ipAttempts,
}: {
  accountAttempts: MockAttempt[];
  ipAttempts: MockAttempt[];
}) {
  return {
    from: (_table: string) => ({
      select: () => createRateLimitQuery(accountAttempts, ipAttempts),
    }),
  };
}

function createRateLimitQuery(accountAttempts: MockAttempt[], ipAttempts: MockAttempt[]) {
  const filters: Record<string, string> = {};
  let windowStart: string | null = null;

  const query = {
    eq(column: string, value: string) {
      filters[column] = value;
      return query;
    },
    gte(_column: string, value: string) {
      windowStart = value;
      return query;
    },
    async order() {
      const source = filters.identifier ? accountAttempts : ipAttempts;
      return {
        data: source.filter((attempt) => (
          !windowStart || attempt.attempted_at >= windowStart
        )),
        error: null,
      };
    },
  };

  return query;
}
