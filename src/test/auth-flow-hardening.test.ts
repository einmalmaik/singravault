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
    expect(resetSource).toContain("finish_opaque_password_reset");
    expect(migrationSourceForSecurityFollowups()).toContain("PERFORM public.revoke_user_auth_sessions");
    expect(resetSource).toContain("sendPasswordResetNotification");
    expect(migrationSourceForSessions()).not.toContain("WHERE user_id = p_user_id::TEXT");
    expect(migrationSourceForSessions()).toContain("information_schema.columns");
  });

  it("centralizes forgot-password and password-change on the OPAQUE reset service", () => {
    const serviceSource = readFileSync("src/services/accountPasswordResetService.ts", "utf-8");
    const authPageSource = readFileSync("src/pages/Auth.tsx", "utf-8");
    const passwordSettingsSource = readFileSync("src/components/settings/PasswordSettings.tsx", "utf-8");
    const networkBodies = extractJsonRequestBodies(serviceSource);

    expect(serviceSource).toContain("Central OPAQUE account-password reset/change flow");
    expect(serviceSource).toContain("requestAccountPasswordEmailCode");
    expect(serviceSource).toContain("verifyAccountPasswordEmailCode");
    expect(serviceSource).toContain("verifyAccountPasswordResetSecondFactor");
    expect(serviceSource).toContain("completeOpaqueAccountPasswordReset");
    expect(serviceSource).toContain("opaqueClient.startRegistration(input.newPassword)");
    expect(serviceSource).toContain("opaqueClient.finishRegistration");
    expect(serviceSource).toContain("'opaque-reset-start'");
    expect(serviceSource).toContain("'opaque-reset-finish'");
    expect(serviceSource).toContain("credentials: 'omit'");
    expect(serviceSource).not.toContain("credentials: 'include'");
    expect(networkBodies).toContain("registrationRequest");
    expect(networkBodies).toContain("registrationRecord");
    expect(networkBodies).not.toContain("newPassword");
    expect(networkBodies).not.toMatch(/\bpassword\s*:/);
    expect(serviceSource).not.toContain("resetPasswordForEmail");
    expect(serviceSource).not.toContain("signInWithPassword");
    expect(serviceSource).not.toContain("updateUser({ password");

    expect(authPageSource).toContain("completeOpaqueAccountPasswordReset");
    expect(authPageSource).toContain("verifyAccountPasswordResetSecondFactor");
    expect(passwordSettingsSource).toContain("completeOpaqueAccountPasswordReset");
    expect(passwordSettingsSource).toContain("requestAccountPasswordEmailCode({ purpose: 'change' })");
    expect(passwordSettingsSource).toContain("canCurrentUserUseAppPasswordFlow");
    expect(authPageSource).toContain("stellt keinen verlorenen Vault-Key wieder her");
    expect(passwordSettingsSource).toContain("stellt keinen verlorenen Vault-Key wieder her");
    expect(passwordSettingsSource).not.toContain("updateUser({ password");
    expect(passwordSettingsSource).not.toContain("resetPasswordForEmail");
  });

  it("requires email-code plus configured 2FA before OPAQUE reset registration", () => {
    const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");
    const resetSource = readFileSync("supabase/functions/auth-reset-password/index.ts", "utf-8");
    const migrationSource = readFileSync("supabase/migrations/20260424193000_opaque_password_reset_change_flow.sql", "utf-8");
    const resetStartSection = extractSection(
      resetSource,
      "async function handleOpaqueResetStart",
      "async function handleOpaqueResetFinish",
    );
    const resetFinishSection = extractSection(
      resetSource,
      "async function handleOpaqueResetFinish",
      "async function findActiveResetChallenge",
    );

    expect(recoverySource).toContain('action === "verify-two-factor"');
    expect(recoverySource).toContain("two_factor_required: twoFactorRequired");
    expect(recoverySource).toContain("authorized_at: twoFactorRequired ? null : nowIso");
    expect(recoverySource).toContain("verifyTwoFactorServer");
    expect(recoverySource).not.toContain("async function verifyAndConsumeBackupCode");
    expect(recoverySource).not.toContain("async function verifyTotpCode");
    expect(resetStartSection).toContain("isResetChallengeAuthorized(challenge)");
    expect(resetStartSection).toContain('"TWO_FACTOR_REQUIRED"');
    expect(resetFinishSection).toContain("isResetChallengeAuthorized(challenge)");
    expect(resetFinishSection).toContain("finish_opaque_password_reset");
    expect(resetSource).toContain('action: "opaque_reset"');
    expect(resetSource).toContain("two_factor_verified_at");
    expect(resetSource).toContain("authorized_at");
    expect(migrationSource).toContain("two_factor_required BOOLEAN NOT NULL DEFAULT FALSE");
    expect(migrationSource).toContain("authorized_at TIMESTAMPTZ");
    expect(migrationSource).toContain("used_at TIMESTAMPTZ");
    expect(migrationSource).toContain("enforce_opaque_no_gotrue_password_on_auth_users");
    expect(migrationSource).toContain("NEW.encrypted_password = NULL");
  });

  it("enforces auth-specific server-side throttling in critical auth paths", () => {
    const helperSource = readFileSync("supabase/functions/_shared/authRateLimit.ts", "utf-8");
    const twoFactorSource = readFileSync("supabase/functions/_shared/twoFactor.ts", "utf-8");
    const auth2faSource = readFileSync("supabase/functions/auth-2fa/index.ts", "utf-8");
    const sessionSource = readFileSync("supabase/functions/auth-session/index.ts", "utf-8");
    const opaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const recoverySource = readFileSync("supabase/functions/auth-recovery/index.ts", "utf-8");
    const migrationSource = [
      readFileSync("supabase/migrations/20260423210000_auth_flow_hardening.sql", "utf-8"),
      readFileSync("supabase/migrations/20260424193000_opaque_password_reset_change_flow.sql", "utf-8"),
      migrationSourceForSecurityFollowups(),
      readFileSync("supabase/migrations/20260425170000_central_two_factor_validation.sql", "utf-8"),
    ].join("\n");
    const registerSource = readFileSync("supabase/functions/auth-register/index.ts", "utf-8");
    const opaqueStartSection = extractSection(
      opaqueSource,
      "async function handleLoginStart",
      "async function handleLoginFinish",
    );

    for (const action of [
      "password_login",
      "recovery_request",
      "recovery_verify",
      "totp_verify",
      "backup_code_verify",
      "login_totp_verify",
      "login_backup_code_verify",
      "password_reset_totp_verify",
      "password_reset_backup_code_verify",
      "vault_totp_verify",
      "vault_backup_code_verify",
      "disable_2fa_verify",
      "critical_2fa_verify",
      "opaque_login",
      "opaque_reset",
      "opaque_register",
    ]) {
      expect(helperSource).toContain(action);
      expect(migrationSource).toContain(action);
    }

    expect(sessionSource).toContain('action: "password_login"');
    expect(sessionSource).not.toContain('action: "totp_verify"');
    expect(sessionSource).not.toContain('action: "backup_code_verify"');
    expect(opaqueSource).toContain('action: "opaque_login"');
    expect(opaqueSource).toContain("verifyTwoFactorServer");
    expect(opaqueSource).toContain("opaqueUnavailableResponse");
    expect(opaqueStartSection).toContain("opaqueUnavailableResponse(opaqueRateLimit, startTime, headers)");
    expect(opaqueStartSection).toContain('invalidOpaqueAttemptResponse(opaqueRateLimit, startTime, headers, "Invalid credentials")');
    expect(opaqueSource).toContain('"INVALID_CREDENTIALS"');
    expect(opaqueSource).not.toContain("OPAQUE_CREDENTIALS_REQUIRED");
    expect(recoverySource).toContain('action: "recovery_verify"');
    expect(registerSource).toContain('action: "opaque_register"');
    expect(registerSource).toContain("checkAuthRateLimit");
    expect(sessionSource).toContain("recordAuthRateLimitFailure");
    expect(opaqueSource).toContain("recordAuthRateLimitFailure");
    expect(recoverySource).toContain("recordAuthRateLimitFailure");
    expect(auth2faSource).toContain("verifyTwoFactorServer");
    expect(auth2faSource).toContain("two_factor_challenges");
    expect(auth2faSource).not.toContain("body.verified");
    expect(twoFactorSource).toContain("verifyAndConsumeBackupCodeServer");
    expect(twoFactorSource).toContain("disable_2fa_verify");
    expect(twoFactorSource).toContain("vault_totp_verify");
  });

  it("allows authenticated Edge Functions to read TOTP secrets only through service-role RPC context", () => {
    const migrationSource = readFileSync(
      "supabase/migrations/20260427190000_allow_service_role_2fa_secret_verification.sql",
      "utf-8",
    );

    expect(migrationSource).toContain("CREATE OR REPLACE FUNCTION public.get_user_2fa_secret");
    expect(migrationSource).toContain("_role TEXT := auth.role()");
    expect(migrationSource).toContain("_role <> 'service_role'");
    expect(migrationSource).toContain("RAISE EXCEPTION 'Forbidden'");
    expect(migrationSource).toContain("GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO authenticated");
    expect(migrationSource).toContain("GRANT EXECUTE ON FUNCTION public.get_user_2fa_secret(UUID, BOOLEAN) TO service_role");
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
    expect(resetSource).toContain("finish_opaque_password_reset");
    expect(registerSource).not.toContain("argon2id");
    expect(resetSource).toContain("OPAQUE password reset required");
    expect(resetSource).not.toContain("newPassword");
    expect(loadtestSource).not.toContain("grant_type=password");
  });

  it("keeps the OPAQUE identifier and server-key/session binding explicit", () => {
    const clientOpaqueSource = readFileSync("src/services/opaqueService.ts", "utf-8");
    const serverOpaqueSource = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
    const migrationSource = readFileSync("supabase/migrations/20260424120000_enforce_opaque_password_auth.sql", "utf-8");
    const registerSource = readFileSync("supabase/functions/auth-register/index.ts", "utf-8");

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
    expect(registerSource).toContain("rollbackRegistrationStart");
    expect(registerSource).toContain("Failed to send signup verification code");
    expect(registerSource).not.toContain("Warning: Failed to trigger signup OTP email after OPAQUE registration");
  });

  it("blocks direct Supabase recovery callbacks and disables URL session detection", () => {
    const authPageSource = readFileSync("src/pages/Auth.tsx", "utf-8");
    const callbackSource = readFileSync("src/platform/tauriOAuthCallback.ts", "utf-8");
    const supabaseClientSource = readFileSync("src/integrations/supabase/client.ts", "utf-8");

    expect(supabaseClientSource).toContain("detectSessionInUrl: false");
    expect(callbackSource).toContain("BLOCKED_SUPABASE_CALLBACK_TYPES");
    expect(callbackSource).toContain('"recovery"');
    expect(callbackSource).toContain('"magiclink"');
    expect(authPageSource).toContain("isBlockedSupabaseAuthCallback");
    expect(authPageSource).toContain("clearPersistentSession");
    expect(authPageSource).not.toContain("type=recovery') ? 'supabase-recovery'");
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

function extractJsonRequestBodies(source: string): string {
  const matches = source.matchAll(/body:\s*JSON\.stringify\(\{([\s\S]*?)\}\),/g);
  return Array.from(matches, (match) => match[1]).join("\n");
}

function migrationSourceForSessions(): string {
  return readFileSync("supabase/migrations/20260423210000_auth_flow_hardening.sql", "utf-8");
}

function migrationSourceForSecurityFollowups(): string {
  return [
    readFileSync("supabase/migrations/20260425120000_security_hardening_followups.sql", "utf-8"),
    readFileSync("supabase/migrations/20260425120001_finish_opaque_password_reset.sql", "utf-8"),
    readFileSync("supabase/migrations/20260425120002_finish_opaque_password_reset_function.sql", "utf-8"),
    readFileSync("supabase/migrations/20260425120003_finish_opaque_password_reset_permissions.sql", "utf-8"),
  ].join("\n");
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
