import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("security hardening contracts", () => {
  it("keeps browser session fallback tokens non-persistent", () => {
    const source = readFileSync("src/services/authSessionManager.ts", "utf-8");

    expect(source).not.toContain("window.sessionStorage.setItem(SESSION_FALLBACK_STORAGE_KEY");
    expect(source).toContain("Remove any token fallback written by older builds");
  });

  it("delivers a production CSP without unsafe script execution", () => {
    const html = readFileSync("index.html", "utf-8");
    const vercel = readFileSync("vercel.json", "utf-8");
    const vite = readFileSync("vite.config.ts", "utf-8");

    expect(html).not.toContain("'unsafe-eval'");
    expect(html).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(vercel).not.toContain("'unsafe-eval'");
    expect(vite).toContain("https://api.pwnedpasswords.com");
  });

  it("binds WebAuthn verification to the exact stored challenge id", () => {
    const source = readFileSync("supabase/functions/webauthn/index.ts", "utf-8");

    expect(source).toContain("Missing challengeId");
    expect(source).toContain('.eq("id", challengeId)');
    expect(source).toContain("getChallengeVerificationScope");
    expect(source).toContain("getWebauthnRateLimitAction");
    expect(source).toContain("recordWebauthnRateLimitOutcome");
    expect(source).toContain("webauthn_challenge");
    expect(source).toContain("webauthn_verify");
    expect(source).toContain("webauthn_manage");
    expect(source).not.toMatch(/from\("webauthn_challenges"\)[\s\S]{0,240}\.order\("created_at"/);
  });

  it("keeps Premium/Admin functions out of the Open-Core Edge Function config", () => {
    const config = readFileSync("supabase/config.toml", "utf-8");
    const manifest = readFileSync("supabase/functions/EDGE_FUNCTION_MANIFEST.md", "utf-8");

    for (const privateFunction of [
      "admin-team",
      "create-checkout-session",
      "create-portal-session",
      "cancel-subscription",
      "stripe-webhook",
      "invite-family-member",
      "accept-family-invitation",
      "invite-emergency-access",
      "support-submit",
      "support-list",
      "support-metrics",
      "desktop-release",
      "admin-support",
      "send-test-mail",
    ]) {
      expect(config).not.toContain(`[functions.${privateFunction}]`);
      expect(manifest).toContain(`\`${privateFunction}\``);
    }
  });

  it("extends the database rate-limit allow-list for account-delete and WebAuthn actions", () => {
    const migration = readFileSync(
      "supabase/migrations/20260428170000_extend_rate_limit_actions_for_edge_hardening.sql",
      "utf-8",
    );
    const sharedRateLimit = readFileSync("supabase/functions/_shared/authRateLimit.ts", "utf-8");

    for (const action of [
      "account_delete",
      "webauthn_challenge",
      "webauthn_verify",
      "webauthn_manage",
    ]) {
      expect(migration).toContain(`'${action}'`);
      expect(sharedRateLimit).toContain(`"${action}"`);
    }
  });

  it("keeps sensitive auth and 2FA helper RPCs service-role only", () => {
    const lintMigration = readFileSync(
      "supabase/migrations/20260428190000_fix_linked_db_lint_errors.sql",
      "utf-8",
    );
    const grantMigration = readFileSync(
      "supabase/migrations/20260428191000_restrict_sensitive_rpc_grants.sql",
      "utf-8",
    );
    const conflictMigration = readFileSync(
      "supabase/migrations/20260428192000_fix_opaque_reset_conflict_target.sql",
      "utf-8",
    );

    expect(lintMigration).toContain("extensions.pgp_sym_decrypt");
    expect(lintMigration).toContain("WHERE user_id::TEXT = p_user_id::TEXT");
    expect(conflictMigration).toContain("ON CONFLICT ON CONSTRAINT user_opaque_records_user_id_key");

    for (const functionSignature of [
      "public.finish_opaque_password_reset(UUID, UUID, TEXT)",
      "public.revoke_user_auth_sessions(UUID)",
      "public.rotate_totp_encryption_key(TEXT)",
      "public.user_2fa_encrypt_secret(TEXT)",
      "public.user_2fa_decrypt_secret(TEXT)",
    ]) {
      expect(grantMigration).toContain(`REVOKE ALL ON FUNCTION ${functionSignature} FROM anon`);
      expect(grantMigration).toContain(`REVOKE ALL ON FUNCTION ${functionSignature} FROM authenticated`);
    }
  });

  it("enforces opaque vault item metadata for future database writes", () => {
    const migration = readFileSync(
      "supabase/migrations/20260427210000_enforce_opaque_vault_item_metadata.sql",
      "utf-8",
    );

    expect(migration).toContain("CREATE TRIGGER enforce_opaque_vault_item_metadata_trigger");
    expect(migration).toContain("BEFORE INSERT OR UPDATE ON public.vault_items");
    expect(migration).toContain("NEW.category_id := NULL");
    expect(migration).not.toContain("UPDATE public.vault_items");
  });

  it("keeps emergency access scoped to hybrid key material and narrow policies", () => {
    const migration = readFileSync(
      "supabase/migrations/20260427212000_harden_emergency_access_and_sync_heads.sql",
      "utf-8",
    );

    expect(migration).toContain("emergency_access_no_legacy_master_key_check");
    expect(migration).toContain("CHECK (encrypted_master_key IS NULL)");
    expect(migration).toContain("Trustees can view granted emergency vault items");
    expect(migration).toContain("ea.pq_encrypted_master_key IS NOT NULL");
    expect(migration).toContain("lower(trusted_email) = lower(current_setting");
    expect(migration).toContain('DROP POLICY IF EXISTS "Grantors can update emergency access"');
  });

  it("uses a monotonic sync head and CAS RPC for queued offline mutations", () => {
    const migration = readFileSync(
      "supabase/migrations/20260427212000_harden_emergency_access_and_sync_heads.sql",
      "utf-8",
    );
    const offlineService = readFileSync("src/services/offlineVaultService.ts", "utf-8");

    expect(migration).toContain("CREATE TABLE IF NOT EXISTS public.vault_sync_heads");
    expect(migration).toContain("CREATE OR REPLACE FUNCTION public.apply_vault_mutation");
    expect(migration).toContain("p_base_revision IS NOT NULL AND _current_revision <> p_base_revision");
    expect(migration).toContain("Mutation vault_id must belong to authenticated user");
    expect(offlineService).toContain("baseRemoteRevision");
    expect(offlineService).toContain("OfflineSnapshotRollbackError");
    expect(offlineService).toContain("apply_vault_mutation");
    expect(offlineService).not.toContain(".from('vault_items')\n          .upsert(mutation.payload");
  });

  it("requires encrypted category metadata for sync RPC and direct category writes", () => {
    const syncMigration = readFileSync(
      "supabase/migrations/20260427212000_harden_emergency_access_and_sync_heads.sql",
      "utf-8",
    );
    const categoryMigration = readFileSync(
      "supabase/migrations/20260428143000_enforce_encrypted_category_metadata.sql",
      "utf-8",
    );

    expect(syncMigration).toContain("Category name must be client-side encrypted");
    expect(syncMigration).toContain("COALESCE(p_payload->>'name', '') NOT LIKE 'enc:cat:v1:%'");
    expect(syncMigration).toContain("parent_id = NULL");
    expect(syncMigration).toContain("sort_order = NULL");

    expect(categoryMigration).toContain("CREATE TRIGGER enforce_encrypted_category_metadata_trigger");
    expect(categoryMigration).toContain("BEFORE INSERT OR UPDATE ON public.categories");
    expect(categoryMigration).toContain("NEW.name, '') NOT LIKE 'enc:cat:v1:%'");
    expect(categoryMigration).toContain("NEW.parent_id := NULL");
    expect(categoryMigration).toContain("NEW.sort_order := NULL");
  });

  it("keeps service worker caching scoped away from Supabase and vault API responses", () => {
    const serviceWorker = readFileSync("src/sw.ts", "utf-8");

    expect(serviceWorker).toContain('url.pathname.startsWith("/assets/")');
    expect(serviceWorker).not.toContain("https://*.supabase.co");
    expect(serviceWorker).not.toContain("supabase.co");
    expect(serviceWorker).not.toMatch(/registerRoute\([\s\S]{0,240}(vault_items|auth-|account-delete|webauthn|functions\/v1)/);
    expect(serviceWorker).not.toContain("cache.put");
  });

  it("stores only non-secret Device Key protection metadata server-side", () => {
    const migration = readFileSync(
      "supabase/migrations/20260428203000_add_vault_protection_mode.sql",
      "utf-8",
    );
    const deviceKeyActivation = readFileSync("src/services/deviceKeyActivationService.ts", "utf-8");
    const deviceKeyUnlock = readFileSync("src/services/deviceKeyUnlockOrchestrator.ts", "utf-8");
    const vaultMasterUnlock = readFileSync("src/services/vaultMasterUnlockService.ts", "utf-8");

    expect(migration).toContain("vault_protection_mode");
    expect(migration).toContain("'master_only'");
    expect(migration).toContain("'device_key_required'");
    expect(migration).toContain("device_key_version");
    expect(migration).toContain("COMMENT ON COLUMN public.profiles.vault_protection_mode");
    expect(migration).not.toMatch(/device_key_(hash|fingerprint|secret|value|material)/i);
    expect(migration).not.toContain("encrypted_device_key");

    expect(deviceKeyActivation).toContain("VAULT_PROTECTION_MODE_DEVICE_KEY_REQUIRED");
    expect(`${deviceKeyUnlock}\n${vaultMasterUnlock}`).toContain("requiresDeviceKey");
    expect(deviceKeyActivation).not.toContain("device_key_hash");
    expect(deviceKeyActivation).not.toContain("device_key_fingerprint");
  });

  it("keeps Tauri Device Key raw material out of generic renderer reads", () => {
    const rust = readFileSync("src-tauri/src/lib.rs", "utf-8");
    const nativeBridge = readFileSync("src/services/deviceKeyNativeBridge.ts", "utf-8");
    const deviceKeyService = readFileSync("src/services/deviceKeyService.ts", "utf-8");

    expect(rust).toContain("derive_device_protected_key");
    expect(rust).toContain("verify_device_key_available");
    expect(rust).toContain("generate_and_store_device_key");
    expect(rust).toContain("export_device_key_for_transfer");
    expect(rust).toContain("import_device_key_from_transfer");
    expect(rust).toContain("normalize_local_secret_key_for_read");
    expect(rust).toContain("local_secret_read_write_blocks_device_key_namespace");
    expect(rust).toContain("normalize_local_secret_key(key, false)");

    expect(nativeBridge).toContain("derive_device_protected_key");
    expect(nativeBridge).not.toContain("load_local_secret");
    expect(deviceKeyService).toContain("Tauri/Desktop keeps raw Device Key material inside Rust/OS keychain");
    expect(deviceKeyService).toContain("return null;");
  });

  it("checks Device Key deactivation confirmation and VaultFA in auth-2fa before profile persistence", () => {
    const auth2fa = readFileSync("supabase/functions/auth-2fa/index.ts", "utf-8");
    const deactivationService = readFileSync("src/services/deviceKeyDeactivationService.ts", "utf-8");
    const migration = readFileSync(
      "supabase/migrations/20260430133000_guard_device_key_deactivation_profile_update.sql",
      "utf-8",
    );

    expect(auth2fa).toContain('DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD = "DISABLE DEVICE KEY"');
    expect(auth2fa).toContain('action === "complete-device-key-deactivation"');
    expect(auth2fa).toContain('confirmationWord !== DEVICE_KEY_DEACTIVATION_CONFIRMATION_WORD');
    expect(auth2fa).toContain('getTwoFactorRequirementServer(supabaseAdmin, userId, "vault_unlock")');
    expect(auth2fa).toContain('method: "totp"');
    expect(auth2fa).toContain('.eq("vault_protection_mode", "device_key_required")');
    expect(auth2fa).not.toMatch(/confirmationWord[\s\S]{0,120}\.toLowerCase\(/);

    expect(deactivationService).toContain("complete-device-key-deactivation");
    expect(deactivationService).not.toContain(".from('profiles')\n    .update({");

    expect(migration).toContain("prevent_direct_device_key_deactivation");
    expect(migration).toContain("auth.role() <> 'service_role'");
    expect(migration).toContain("OLD.vault_protection_mode = 'device_key_required'");
    expect(migration).toContain("NEW.vault_protection_mode = 'master_only'");
    expect(migration).toContain("device_key_deactivation_requires_server_validation");
  });

  it("centralizes server-visible vault item metadata neutralization for new writes", () => {
    const policy = readFileSync("src/services/vaultMetadataPolicy.ts", "utf-8");
    const itemDialog = readFileSync("src/components/vault/VaultItemDialog.tsx", "utf-8");
    const categoryDialog = readFileSync("src/components/vault/CategoryDialog.tsx", "utf-8");
    const offlineService = readFileSync("src/services/offlineVaultService.ts", "utf-8");
    const recoveryService = readFileSync("src/services/vaultQuarantineRecoveryService.ts", "utf-8");
    const legacyMigrationService = readFileSync("src/services/legacyVaultMetadataMigrationService.ts", "utf-8");

    expect(policy).toContain("neutralizeVaultItemServerMetadata");
    expect(policy).toContain("hasLegacyVaultItemServerMetadata");
    expect(policy).toContain("mergeLegacyVaultItemMetadataIntoPayload");
    expect(itemDialog).toContain("neutralizeVaultItemServerMetadata");
    expect(categoryDialog).toContain("neutralizeVaultItemServerMetadata");
    expect(offlineService).toContain("neutralizeVaultItemServerMetadata(mutation.payload)");
    expect(recoveryService).toContain("neutralizeVaultItemServerMetadata");
    expect(legacyMigrationService).toContain("migrateLegacyVaultItemMetadata");
    expect(legacyMigrationService).toContain(".eq('user_id', input.userId)");
  });
});
