-- Copyright (c) 2025-2026 Maunting Studios
-- Licensed under the Business Source License 1.1 - see LICENSE
/**
 * RPC helper for cross-platform migration detection.
 *
 * Safely checks whether a manifest record exists for the given vault
 * without exposing any sensitive payload or requiring a vault key.
 * Used by evaluateVaultMigrationGate to detect platform-completed migrations
 * from a client that has no local completion marker.
 *
 * A manifest record is created when the legacy-to-op-log migration commits.
 * Its existence proves that a trusted device has already migrated this vault.
 */
create or replace function op_log_manifest_exists(p_vault_id text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  return exists (
    select 1
    from public.vault_records
    where vault_id = p_vault_id::uuid
      and record_type = 'manifest'
    limit 1
  );
end;
$$;

revoke all on function op_log_manifest_exists(text) from public, anon;
grant execute on function op_log_manifest_exists(text) to authenticated, service_role;
