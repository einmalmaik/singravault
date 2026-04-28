-- Metadata zero-knowledge verification queries.
--
-- Run against a staging or local Supabase database after applying migrations.
-- These queries do not mutate data. They separate legacy rows from future-write
-- guardrail failures so operators can migrate without blind data deletion.

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
