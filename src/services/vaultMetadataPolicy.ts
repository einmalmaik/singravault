// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

export const ENCRYPTED_ITEM_TITLE_PLACEHOLDER = 'Encrypted Item';
export const ENCRYPTED_CATEGORY_PREFIX = 'enc:cat:v1:';
export const NEUTRAL_SERVER_ITEM_TYPE = 'password';

export interface VaultItemServerMetadata {
  title?: string | null;
  website_url?: string | null;
  icon_url?: string | null;
  item_type?: string | null;
  is_favorite?: boolean | null;
  category_id?: string | null;
  sort_order?: number | null;
  last_used_at?: string | null;
}

/**
 * Server-visible vault item metadata is compatibility-only. User-meaningful
 * title, URL, username, type, favorite/category intent, tags and notes belong
 * inside `encrypted_data`. Use this before every new item upsert or queued
 * mutation so old callers cannot accidentally persist plaintext metadata.
 */
export function neutralizeVaultItemServerMetadata<T extends VaultItemServerMetadata>(
  row: T,
): T & {
  title: typeof ENCRYPTED_ITEM_TITLE_PLACEHOLDER;
  website_url: null;
  icon_url: null;
  item_type: typeof NEUTRAL_SERVER_ITEM_TYPE;
  is_favorite: false;
  category_id: null;
  sort_order: null;
  last_used_at: null;
} {
  return {
    ...row,
    title: ENCRYPTED_ITEM_TITLE_PLACEHOLDER,
    website_url: null,
    icon_url: null,
    item_type: NEUTRAL_SERVER_ITEM_TYPE,
    is_favorite: false,
    category_id: null,
    sort_order: null,
    last_used_at: null,
  };
}

export function isNeutralVaultItemServerMetadata(row: VaultItemServerMetadata): boolean {
  return row.title === ENCRYPTED_ITEM_TITLE_PLACEHOLDER
    && row.website_url === null
    && row.icon_url === null
    && row.item_type === NEUTRAL_SERVER_ITEM_TYPE
    && row.is_favorite === false
    && row.category_id === null
    && row.sort_order === null
    && row.last_used_at === null;
}

export function isEncryptedCategoryMetadataValue(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.startsWith(ENCRYPTED_CATEGORY_PREFIX);
}
