-- Metadata zero-knowledge verification queries.
--
-- Run against a staging or local Supabase database after applying migrations.
-- These queries do not mutate data. They separate legacy rows from future-write
-- guardrail failures so operators can migrate without blind data deletion.
-- 2026-04-28 deploy note: the linked project schema was verified with
-- `supabase db lint --linked`, `supabase migration list`, and a remote schema
-- dump. Execute this file with psql or the Supabase SQL editor for row-level
-- counts before release; avoid data-only dumps because they can write user or
-- account data to disk.

-- 1. Future-write invariant: no new/neutralized vault item row should expose
-- semantic metadata outside encrypted_data.
SELECT
  id,
  user_id,
  title,
  website_url,
  icon_url,
  item_type,
  is_favorite,
  category_id,
  sort_order,
  last_used_at,
  updated_at
FROM public.vault_items
WHERE title = 'Encrypted Item'
  AND (
    website_url IS NOT NULL
    OR icon_url IS NOT NULL
    OR item_type IS DISTINCT FROM 'password'
    OR is_favorite IS DISTINCT FROM false
    OR category_id IS NOT NULL
    OR sort_order IS NOT NULL
    OR last_used_at IS NOT NULL
  );

-- 2. Legacy rows still requiring client-side re-encryption/migration.
SELECT
  id,
  user_id,
  title,
  website_url IS NOT NULL AS has_website_url,
  icon_url IS NOT NULL AS has_icon_url,
  item_type,
  is_favorite,
  category_id IS NOT NULL AS has_category_id,
  sort_order IS NOT NULL AS has_sort_order,
  last_used_at IS NOT NULL AS has_last_used_at,
  updated_at
FROM public.vault_items
WHERE title IS DISTINCT FROM 'Encrypted Item'
   OR website_url IS NOT NULL
   OR icon_url IS NOT NULL
   OR item_type IS DISTINCT FROM 'password'
   OR is_favorite IS DISTINCT FROM false
   OR category_id IS NOT NULL
   OR sort_order IS NOT NULL
   OR last_used_at IS NOT NULL
ORDER BY updated_at DESC;

-- 3. Category metadata must be encrypted and hierarchy/sort metadata neutral.
SELECT
  id,
  user_id,
  name,
  icon,
  color,
  parent_id,
  sort_order,
  updated_at
FROM public.categories
WHERE COALESCE(name, '') NOT LIKE 'enc:cat:v1:%'
   OR (icon IS NOT NULL AND icon NOT LIKE 'enc:cat:v1:%')
   OR (color IS NOT NULL AND color NOT LIKE 'enc:cat:v1:%')
   OR parent_id IS NOT NULL
   OR sort_order IS NOT NULL
ORDER BY updated_at DESC;

-- 4. Trigger presence checks.
SELECT
  event_object_table,
  trigger_name,
  action_timing,
  event_manipulation
FROM information_schema.triggers
WHERE event_object_schema = 'public'
  AND trigger_name IN (
    'enforce_opaque_vault_item_metadata_trigger',
    'enforce_encrypted_category_metadata_trigger'
  )
ORDER BY event_object_table, trigger_name, event_manipulation;

-- 5. RLS must remain enabled on exposed vault metadata tables.
SELECT
  schemaname,
  tablename,
  rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN (
    'vault_items',
    'categories',
    'vault_item_tags',
    'tags',
    'file_attachments',
    'vault_sync_heads'
  )
  AND rowsecurity IS DISTINCT FROM true
ORDER BY tablename;

-- 6. Core attachment metadata must not expose semantic names or MIME values.
-- This is expected to return zero rows for Open-Core deployments. Premium
-- attachment implementations must keep encrypted_metadata populated and use
-- opaque storage paths rather than original filenames.
SELECT
  id,
  user_id,
  vault_item_id,
  file_name,
  mime_type,
  storage_path,
  encrypted,
  encrypted_metadata IS NOT NULL AS has_encrypted_metadata
FROM public.file_attachments
WHERE encrypted IS DISTINCT FROM true
   OR encrypted_metadata IS NULL
   OR file_name !~ '^attachment-[0-9a-f-]{36}$'
   OR mime_type IS NOT NULL
   OR storage_path ~* '[[:alnum:]_-]+\\.(pdf|docx?|xlsx?|png|jpe?g|gif|txt|csv|zip)$'
ORDER BY updated_at DESC;

-- 7. Vault item rows must not carry TOTP/account-secret shaped values in
-- compatibility metadata columns. Real Vault TOTP secrets belong in encrypted_data.
SELECT
  id,
  user_id,
  title,
  website_url,
  icon_url
FROM public.vault_items
WHERE title ~* '(totp|secret|otp|otpauth)'
   OR COALESCE(website_url, '') ~* '(otpauth://|secret=)'
   OR COALESCE(icon_url, '') ~* '(otpauth://|secret=)';

-- 8. Rate-limit action allow-list must include current critical Edge actions.
SELECT
  conname,
  pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conrelid = 'public.rate_limit_attempts'::regclass
  AND conname = 'rate_limit_attempts_action_check'
  AND (
    pg_get_constraintdef(oid) NOT LIKE '%account_delete%'
    OR pg_get_constraintdef(oid) NOT LIKE '%webauthn_challenge%'
    OR pg_get_constraintdef(oid) NOT LIKE '%webauthn_verify%'
    OR pg_get_constraintdef(oid) NOT LIKE '%webauthn_manage%'
  );
