-- Secure Supabase Storage bucket for encrypted vault attachments.
--
-- This project encrypts attachment bytes client-side, but we still must
-- enforce least-privilege access to Storage objects via RLS.

-- Ensure the bucket exists and is private.
insert into storage.buckets (id, name, public)
values ('vault-attachments', 'vault-attachments', false)
on conflict (id)
do update set public = false;

-- Enforce RLS on storage objects when the local migration role owns the
-- Storage table. Some Supabase-local CLI/runtime combinations apply project
-- migrations without ownership on `storage.objects`; in that case the hosted
-- Storage service remains responsible for its own RLS baseline and we still
-- create the bucket below without weakening public access.
do $$
begin
  begin
    alter table storage.objects enable row level security;
  exception
    when insufficient_privilege then
      raise notice 'Skipping storage.objects RLS enablement: migration role is not table owner';
  end;
end $$;

-- Policies: authenticated users can only access their own objects
-- within the vault-attachments bucket.

do $$
begin
  begin
    drop policy if exists "vault_attachments_select_own" on storage.objects;
    create policy "vault_attachments_select_own"
    on storage.objects
    for select
    to authenticated
    using (
        bucket_id = 'vault-attachments'
        and owner = auth.uid()
    );

    drop policy if exists "vault_attachments_insert_own" on storage.objects;
    create policy "vault_attachments_insert_own"
    on storage.objects
    for insert
    to authenticated
    with check (
        bucket_id = 'vault-attachments'
        and owner = auth.uid()
    );

    drop policy if exists "vault_attachments_delete_own" on storage.objects;
    create policy "vault_attachments_delete_own"
    on storage.objects
    for delete
    to authenticated
    using (
        bucket_id = 'vault-attachments'
        and owner = auth.uid()
    );
  exception
    when insufficient_privilege then
      raise notice 'Skipping vault attachment storage policies: migration role is not storage.objects owner';
  end;
end $$;
