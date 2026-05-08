-- Copyright (c) 2025-2026 Maunting Studios
-- Licensed under the Business Source License 1.1 - see LICENSE
/**
 * RPC helper for non-authoritative cross-platform migration diagnostics.
 *
 * This function may only answer for caller-owned vaults. Its result is
 * not a trust source and must not unlock a vault without local cryptographic
 * OpLog verification using the vault key.
 *
 * A manifest record is created when the legacy-to-op-log migration commits,
 * but existence alone does not prove that the record is valid, decryptable,
 * signed by a trusted device, or part of the verified head chain.
 */
create or replace function op_log_manifest_exists(p_vault_id text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  _uid uuid := auth.uid();
  _vault_id uuid := p_vault_id::uuid;
begin
  if _uid is null then
    raise exception 'Not authenticated';
  end if;

  if not exists (
    select 1
    from public.vaults
    where id = _vault_id
      and user_id = _uid
  ) then
    raise exception 'Vault does not belong to caller';
  end if;

  return exists (
    select 1
    from public.vault_records
    where vault_id = _vault_id
      and user_id = _uid
      and record_type = 'manifest'
    limit 1
  );
end;
$$;

revoke all on function op_log_manifest_exists(text) from public, anon;
grant execute on function op_log_manifest_exists(text) to authenticated, service_role;
