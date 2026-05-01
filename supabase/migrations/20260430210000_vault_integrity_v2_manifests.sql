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

create or replace function public.apply_vault_mutation_v2(
  p_base_revision bigint,
  p_type text,
  p_payload jsonb,
  p_expected_manifest_revision bigint,
  p_expected_manifest_hash text,
  p_manifest_revision bigint,
  p_manifest_hash text,
  p_previous_manifest_hash text,
  p_key_id text,
  p_manifest_envelope text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  _uid uuid := auth.uid();
  _vault_id uuid;
  _current_revision bigint := 0;
  _next_revision bigint := 0;
  _current_manifest public.vault_integrity_manifests%rowtype;
  _item_id uuid;
  _category_id uuid;
  _affected_rows integer := 0;
begin
  if _uid is null then
    raise exception 'Not authenticated';
  end if;

  if p_type not in ('upsert_item', 'delete_item', 'upsert_category', 'delete_category', 'restore_item') then
    raise exception 'Unsupported vault mutation type';
  end if;

  if p_type in ('upsert_item', 'delete_item', 'restore_item') then
    _item_id := (p_payload->>'id')::uuid;
    if p_type in ('upsert_item', 'restore_item') then
      _vault_id := (p_payload->>'vault_id')::uuid;
      if (p_payload->>'user_id')::uuid is distinct from _uid then
        raise exception 'Mutation user_id must match authenticated user';
      end if;
      if not exists (
        select 1 from public.vaults where id = _vault_id and user_id = _uid
      ) then
        raise exception 'Mutation vault_id must belong to authenticated user';
      end if;
    else
      select vault_id into _vault_id
      from public.vault_items
      where id = _item_id and user_id = _uid;

      if _vault_id is null and p_payload ? 'vault_id' then
        _vault_id := (p_payload->>'vault_id')::uuid;
      end if;
    end if;
  else
    _category_id := (p_payload->>'id')::uuid;
    if p_type = 'upsert_category' and (p_payload->>'user_id')::uuid is distinct from _uid then
      raise exception 'Mutation user_id must match authenticated user';
    end if;

    select id into _vault_id
    from public.vaults
    where user_id = _uid and is_default = true
    order by created_at asc
    limit 1;
  end if;

  if _vault_id is null then
    return jsonb_build_object('applied', false, 'conflict_reason', 'missing_vault');
  end if;

  if not exists (
    select 1
    from public.vaults
    where id = _vault_id and user_id = _uid
  ) then
    raise exception 'Mutation vault_id must belong to authenticated user';
  end if;

  if p_manifest_revision is null or p_manifest_revision < 1 then
    raise exception 'Manifest revision is required';
  end if;

  insert into public.vault_sync_heads (vault_id, user_id, revision, updated_at)
  values (_vault_id, _uid, 0, now())
  on conflict (vault_id) do nothing;

  select revision into _current_revision
  from public.vault_sync_heads
  where vault_id = _vault_id and user_id = _uid
  for update;

  select * into _current_manifest
  from public.vault_integrity_manifests
  where vault_id = _vault_id and user_id = _uid
  for update;

  if p_base_revision is not null and _current_revision <> p_base_revision then
    return jsonb_build_object(
      'applied', false,
      'revision', _current_revision,
      'manifest_revision', _current_manifest.manifest_revision,
      'conflict_reason', 'stale_base_revision'
    );
  end if;

  if _current_manifest.vault_id is not null then
    if p_expected_manifest_revision is not null
       and _current_manifest.manifest_revision <> p_expected_manifest_revision then
      return jsonb_build_object(
        'applied', false,
        'revision', _current_revision,
        'manifest_revision', _current_manifest.manifest_revision,
        'conflict_reason', 'stale_manifest_revision'
      );
    end if;

    if p_expected_manifest_hash is not null
       and _current_manifest.manifest_hash <> p_expected_manifest_hash then
      return jsonb_build_object(
        'applied', false,
        'revision', _current_revision,
        'manifest_revision', _current_manifest.manifest_revision,
        'conflict_reason', 'stale_manifest_hash'
      );
    end if;
  elsif p_expected_manifest_revision is not null or p_expected_manifest_hash is not null then
    return jsonb_build_object(
      'applied', false,
      'revision', _current_revision,
      'manifest_revision', null,
      'conflict_reason', 'manifest_missing'
    );
  end if;

  if p_type in ('upsert_item', 'restore_item') then
    insert into public.vault_items (
      id, user_id, vault_id, title, website_url, icon_url, item_type,
      encrypted_data, category_id, is_favorite, sort_order, last_used_at
    )
    values (
      _item_id,
      _uid,
      _vault_id,
      coalesce(p_payload->>'title', 'Encrypted Item'),
      p_payload->>'website_url',
      p_payload->>'icon_url',
      coalesce(p_payload->>'item_type', 'password')::public.vault_item_type,
      p_payload->>'encrypted_data',
      nullif(p_payload->>'category_id', '')::uuid,
      coalesce((p_payload->>'is_favorite')::boolean, false),
      nullif(p_payload->>'sort_order', '')::integer,
      nullif(p_payload->>'last_used_at', '')::timestamptz
    )
    on conflict (id) do update
    set encrypted_data = excluded.encrypted_data,
        item_type = excluded.item_type,
        category_id = excluded.category_id,
        updated_at = now()
    where public.vault_items.user_id = _uid
      and public.vault_items.vault_id = _vault_id;

    get diagnostics _affected_rows = row_count;
    if _affected_rows = 0 then
      return jsonb_build_object(
        'applied', false,
        'revision', _current_revision,
        'manifest_revision', _current_manifest.manifest_revision,
        'conflict_reason', 'ownership_conflict'
      );
    end if;
  elsif p_type = 'delete_item' then
    delete from public.vault_items
    where id = _item_id and user_id = _uid;
  elsif p_type = 'upsert_category' then
    perform public.assert_encrypted_category_metadata(
      p_payload->>'name',
      p_payload->>'icon',
      p_payload->>'color'
    );

    insert into public.categories (id, user_id, name, icon, color, parent_id, sort_order)
    values (
      _category_id,
      _uid,
      p_payload->>'name',
      p_payload->>'icon',
      p_payload->>'color',
      nullif(p_payload->>'parent_id', '')::uuid,
      nullif(p_payload->>'sort_order', '')::integer
    )
    on conflict (id) do update
    set name = excluded.name,
        icon = excluded.icon,
        color = excluded.color,
        parent_id = excluded.parent_id,
        sort_order = excluded.sort_order,
        updated_at = now()
    where public.categories.user_id = _uid;

    get diagnostics _affected_rows = row_count;
    if _affected_rows = 0 then
      return jsonb_build_object(
        'applied', false,
        'revision', _current_revision,
        'manifest_revision', _current_manifest.manifest_revision,
        'conflict_reason', 'ownership_conflict'
      );
    end if;
  elsif p_type = 'delete_category' then
    delete from public.categories
    where id = _category_id and user_id = _uid;
  end if;

  insert into public.vault_integrity_manifests (
    vault_id, user_id, manifest_revision, manifest_hash,
    previous_manifest_hash, key_id, manifest_envelope, updated_at
  )
  values (
    _vault_id, _uid, p_manifest_revision, p_manifest_hash,
    p_previous_manifest_hash, p_key_id, p_manifest_envelope, now()
  )
  on conflict (vault_id) do update
  set manifest_revision = excluded.manifest_revision,
      manifest_hash = excluded.manifest_hash,
      previous_manifest_hash = excluded.previous_manifest_hash,
      key_id = excluded.key_id,
      manifest_envelope = excluded.manifest_envelope,
      updated_at = now()
  where public.vault_integrity_manifests.user_id = _uid;

  get diagnostics _affected_rows = row_count;
  if _affected_rows = 0 then
    return jsonb_build_object(
      'applied', false,
      'revision', _current_revision,
      'manifest_revision', _current_manifest.manifest_revision,
      'conflict_reason', 'ownership_conflict'
    );
  end if;

  select revision into _next_revision
  from public.vault_sync_heads
  where vault_id = _vault_id and user_id = _uid;

  return jsonb_build_object(
    'applied', true,
    'revision', coalesce(_next_revision, _current_revision),
    'manifest_revision', p_manifest_revision,
    'conflict_reason', null
  );
end;
$$;

revoke all on function public.apply_vault_mutation_v2(
  bigint, text, jsonb, bigint, text, bigint, text, text, text, text
) from public;
grant execute on function public.apply_vault_mutation_v2(
  bigint, text, jsonb, bigint, text, bigint, text, text, text, text
) to authenticated;

comment on function public.apply_vault_mutation_v2(
  bigint, text, jsonb, bigint, text, bigint, text, text, text, text
) is
  'Applies a vault item/category mutation and Manifest V2 envelope in one revision-checked transaction. Conflicts return applied=false and must not be treated as item quarantine.';
