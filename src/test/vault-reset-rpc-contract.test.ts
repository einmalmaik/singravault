import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const migrationSource = readFileSync(
  'supabase/migrations/20260423193000_harden_vault_reset_recovery.sql',
  'utf-8',
);

describe('vault reset RPC contract', () => {
  it('requires fresh reauthentication before issuing a reset challenge', () => {
    expect(migrationSource).toContain('CREATE OR REPLACE FUNCTION public.require_recent_reauthentication');
    expect(migrationSource).toContain("_iat_text := _jwt ->> 'iat';");
    expect(migrationSource).toContain("RAISE EXCEPTION 'REAUTH_REQUIRED';");
    expect(migrationSource).toContain("IF _iat > (_now_epoch + 30) OR (_now_epoch - _iat) > p_max_age_seconds THEN");
    expect(migrationSource).toContain("RETURN public.issue_sensitive_action_challenge('vault_reset_recovery', 300);");
  });

  it('stores the recovery state as a short-lived one-time server challenge', () => {
    expect(migrationSource).toContain('CREATE TABLE IF NOT EXISTS public.sensitive_action_challenges');
    expect(migrationSource).toContain('UNIQUE (user_id, action)');
    expect(migrationSource).toContain('expires_at TIMESTAMPTZ NOT NULL');
    expect(migrationSource).toContain('CREATE OR REPLACE FUNCTION public.consume_sensitive_action_challenge');
    expect(migrationSource).toContain("RAISE EXCEPTION 'RECOVERY_CHALLENGE_REQUIRED';");
  });

  it('requires a recovery challenge parameter on reset_user_vault_state and consumes it before wiping data', () => {
    expect(migrationSource).toContain('CREATE OR REPLACE FUNCTION public.reset_user_vault_state(');
    expect(migrationSource).toContain('p_recovery_challenge_id UUID');
    expect(migrationSource).toContain("PERFORM public.require_recent_reauthentication(300);");
    expect(migrationSource).toContain("PERFORM public.consume_sensitive_action_challenge(");
    expect(migrationSource).toContain("'vault_reset_recovery'");
    expect(migrationSource).toContain('p_recovery_challenge_id');
    expect(migrationSource).toContain("DELETE FROM storage.objects");
  });
});
