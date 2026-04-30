-- Vault Integrity & Quarantine V2 manifest envelopes.
-- The encrypted manifest envelope is client-authenticated with Vault-AAD V2.
-- The server stores and gates revisions, but never becomes a trust source for
-- item membership or category structure.

create table if not exists public.vault_integrity_manifests (
  vault_id uuid primary key references public.vaults(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  manifest_revision bigint not null check (manifest_revision >= 0),
  manifest_hash text not null,
  previous_manifest_hash text,
  key_id text not null,
  manifest_envelope text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists vault_integrity_manifests_user_id_idx
  on public.vault_integrity_manifests(user_id);

alter table public.vault_integrity_manifests enable row level security;

drop policy if exists "vault manifest select own vault" on public.vault_integrity_manifests;
create policy "vault manifest select own vault"
  on public.vault_integrity_manifests
  for select
  using (
    auth.uid() = user_id
    and exists (
      select 1
      from public.vaults v
      where v.id = vault_integrity_manifests.vault_id
        and v.user_id = auth.uid()
    )
  );

drop policy if exists "vault manifest insert own vault" on public.vault_integrity_manifests;
create policy "vault manifest insert own vault"
  on public.vault_integrity_manifests
  for insert
  with check (
    auth.uid() = user_id
    and exists (
      select 1
      from public.vaults v
      where v.id = vault_integrity_manifests.vault_id
        and v.user_id = auth.uid()
    )
  );

drop policy if exists "vault manifest update own vault" on public.vault_integrity_manifests;
create policy "vault manifest update own vault"
  on public.vault_integrity_manifests
  for update
  using (
    auth.uid() = user_id
    and exists (
      select 1
      from public.vaults v
      where v.id = vault_integrity_manifests.vault_id
        and v.user_id = auth.uid()
    )
  )
  with check (
    auth.uid() = user_id
    and exists (
      select 1
      from public.vaults v
      where v.id = vault_integrity_manifests.vault_id
        and v.user_id = auth.uid()
    )
  );

create or replace function public.touch_vault_integrity_manifest_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists touch_vault_integrity_manifests_updated_at
  on public.vault_integrity_manifests;
create trigger touch_vault_integrity_manifests_updated_at
  before update on public.vault_integrity_manifests
  for each row
  execute function public.touch_vault_integrity_manifest_updated_at();
