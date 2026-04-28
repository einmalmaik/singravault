import { readFileSync } from "node:fs";

describe("account deletion and auth runtime hardening", () => {
  const migration = readFileSync(
    "supabase/migrations/20260426193000_harden_account_delete_and_opaque_orphans.sql",
    "utf-8",
  );
  const storageApiMigration = readFileSync(
    "supabase/migrations/20260428153000_remove_direct_storage_delete_from_account_delete.sql",
    "utf-8",
  );
  const accountSettings = readFileSync("src/components/settings/AccountSettings.tsx", "utf-8");
  const accountDeleteFunction = readFileSync("supabase/functions/account-delete/index.ts", "utf-8");
  const authRegister = readFileSync("supabase/functions/auth-register/index.ts", "utf-8");
  const authOpaque = readFileSync("supabase/functions/auth-opaque/index.ts", "utf-8");
  const authErrors = readFileSync("supabase/functions/_shared/authErrors.ts", "utf-8");
  const cors = readFileSync("supabase/functions/_shared/cors.ts", "utf-8");

  it("prevents orphaned OPAQUE records with cleanup and cascading foreign keys", () => {
    expect(migration).toContain("DELETE FROM public.user_opaque_records records");
    expect(migration).toContain("FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE");
    expect(migration).toContain("DELETE FROM public.opaque_login_states states");
    expect(migration).toContain("opaque_identifier = _email");
  });

  it("requires fresh reauth and verified 2FA before deleting accounts with 2FA enabled", () => {
    expect(migration).toContain("REAUTH_REQUIRED");
    expect(migration).toContain("ACCOUNT_DELETE_2FA_REQUIRED");
    expect(migration).toContain("p_two_factor_challenge_id UUID DEFAULT NULL");
    expect(migration).toContain("purpose = 'critical_action'");
    expect(migration).toContain("method = 'totp'");
  });

  it("deletes core user-owned data and audits for leftovers before returning success", () => {
    [
      "vault_item_tags",
      "vault_items",
      "categories",
      "tags",
      "vaults",
      "user_roles",
      "user_opaque_records",
      "opaque_login_states",
      "opaque_password_reset_states",
      "user_keys",
      "user_2fa",
      "backup_codes",
      "sensitive_action_challenges",
      "passkey_credentials",
      "subscriptions",
      "file_attachments",
    ].forEach((table) => expect(migration).toContain(table));

    expect(migration).toContain("ACCOUNT_DELETE_INCOMPLETE");
    expect(migration).toContain("DELETE FROM auth.users WHERE id = _uid");
  });

  it("keeps account deletion storage cleanup on the Storage API instead of direct storage table deletes", () => {
    expect(storageApiMigration).toContain("CREATE OR REPLACE FUNCTION public.delete_my_account");
    expect(storageApiMigration).not.toContain("DELETE FROM storage.objects");
    expect(accountSettings).toContain("invokeAuthedFunction<{ deleted?: boolean }>('account-delete'");
    expect(accountSettings).not.toContain("supabase.rpc('delete_my_account'");
    expect(accountSettings).toContain("isEdgeFunctionServiceError");
    expect(accountSettings).toContain("isAccountDeleteReauthRequired");
    expect(accountDeleteFunction).toContain('userClient.rpc("delete_my_account"');
    expect(accountDeleteFunction).toContain(".storage");
    expect(accountDeleteFunction).toContain(".remove(batch)");
    expect(accountDeleteFunction).toContain('ATTACHMENTS_BUCKET = "vault-attachments"');
    expect(accountDeleteFunction).toContain("storage_cleanup_failed");
    expect(accountDeleteFunction).toContain('allowedMethods: "POST, OPTIONS"');
  });

  it("keeps account-delete UI export/2FA warning outside nested paragraph descriptions", () => {
    expect(accountSettings).toContain("<AlertDialogDescription asChild>");
    expect(accountSettings).toContain("exportBeforeDelete");
    expect(accountSettings).toContain("deleteTwoFactorLabel");
    expect(accountSettings).toContain("verifyTwoFactorChallenge");
    expect(accountSettings).toContain("method: 'totp'");
    expect(accountSettings).not.toContain("method: useBackupCode ? 'backup_code' : 'totp'");
  });

  it("uses stable auth error codes instead of leaking raw OPAQUE/database errors", () => {
    [
      "ACCOUNT_ALREADY_EXISTS",
      "OPAQUE_RECORD_CONFLICT",
      "OPAQUE_REGISTRATION_FAILED",
      "AUTH_EMAIL_ALREADY_IN_USE",
      "AUTH_INVALID_OR_EXPIRED_CODE",
      "TOO_MANY_ATTEMPTS",
      "AUTH_REQUIRED",
      "FORBIDDEN",
      "SERVER_ERROR",
    ].forEach((code) => expect(authErrors).toContain(code));

    expect(authRegister).toContain("jsonError(");
    expect(authRegister).toContain("sanitizeAuthError");
    expect(authOpaque).toContain("OPAQUE_RECORD_CONFLICT");
    expect(authRegister).not.toContain("duplicate key value");
  });

  it("does not allow localhost CORS unless explicitly configured", () => {
    expect(cors).toContain("ALLOW_LOCAL_DEV_ORIGINS");
    expect(cors).toContain("ALLOWED_DEV_ORIGINS");
    expect(cors).toContain("configuredLocalDevOrigins.includes(origin)");
    expect(cors).not.toContain("origin.startsWith(\"http://localhost:\")");
  });

  it("keeps Supabase types aligned with late-April auth and account-deletion columns", () => {
    const types = readFileSync("src/integrations/supabase/types.ts", "utf-8");

    [
      "opaque_identifier: string | null",
      "encrypted_user_key: string | null",
      "opaque_registration_challenges",
      "opaque_password_reset_states",
      "opaque_reenrollment_required",
      "password_reset_challenges",
      "two_factor_challenges",
      "authorized_at: string | null",
      "two_factor_required: boolean",
      "used_at: string | null",
    ].forEach((snippet) => expect(types).toContain(snippet));
  });
});
