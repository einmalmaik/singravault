// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

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
    expect(resetSource).toContain("sendPasswordResetNotification");
  });

  it("enforces auth-specific server-side throttling in critical auth paths", () => {
    const helperSource = readFileSync("supabase/functions/_shared/authRateLimit.ts", "utf-8");
    const sessionSource = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");
    const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");
    const migrationSource = readFileSync("supabase/migrations/20260423210000_auth_flow_hardening.sql", "utf-8");

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
    expect(sessionSource).toContain('action: "totp_verify"');
    expect(sessionSource).toContain('action: "backup_code_verify"');
    expect(opaqueSource).toContain('action: "opaque_login"');
    expect(opaqueSource).toContain('action: isBackupCode ? "backup_code_verify" : "totp_verify"');
    expect(recoverySource).toContain('action: "recovery_verify"');
    expect(sessionSource).toContain("recordAuthRateLimitFailure");
    expect(opaqueSource).toContain("recordAuthRateLimitFailure");
    expect(recoverySource).toContain("recordAuthRateLimitFailure");
  });
});

function extractSection(source: string, startNeedle: string, endNeedle: string): string {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}
