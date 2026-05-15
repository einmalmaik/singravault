// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item Plaintext Mapper
 *
 * Converts verified OpLog records to the UI-facing `VaultItem` shape and back to
 * `ItemPlaintext` payloads suitable for writes.
 *
 * The list view edits two fields locally (favorite + category) but must still
 * round-trip the rest of the plaintext faithfully, otherwise an inline favorite
 * toggle could silently drop totp/customFields data. The mapper is therefore
 * conservative: it only overrides what the caller asked for and reads every
 * other field from the verified plaintext when available.
 */

import type { VaultItemData } from '@/services/cryptoService';
import type { ItemPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';

import {
  isStringRecord,
  isTotpAlgorithm,
  isVaultItemType,
  type VaultItem,
} from './vaultItemModel';

export interface CategorySummary {
  readonly id: string;
  readonly name: string;
}

function isVerifiedRecord(record: LocalVerifiedRecord): boolean {
  return record.recordState === 'verified' || record.recordState === 'restoredFromSnapshot';
}

export function parseOpLogItemPlaintext(record: LocalVerifiedRecord): VaultItemData | null {
  if (!isVerifiedRecord(record) || record.record.recordType !== 'item' || !record.plaintext) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const value = parsed as Record<string, unknown>;
    const title = typeof value.title === 'string' ? value.title : '';
    const itemType = isVaultItemType(value.itemType) ? value.itemType : 'password';

    return {
      title,
      websiteUrl: typeof value.websiteUrl === 'string' ? value.websiteUrl : undefined,
      username: typeof value.username === 'string' ? value.username : undefined,
      password: typeof value.password === 'string' ? value.password : undefined,
      notes: typeof value.notes === 'string' ? value.notes : undefined,
      itemType,
      categoryId: typeof value.categoryRecordId === 'string' ? value.categoryRecordId : null,
      isFavorite: typeof value.isFavorite === 'boolean' ? value.isFavorite : false,
      totpSecret: typeof value.totpSecret === 'string' ? value.totpSecret : undefined,
      totpIssuer: typeof value.totpIssuer === 'string' ? value.totpIssuer : undefined,
      totpLabel: typeof value.totpLabel === 'string' ? value.totpLabel : undefined,
      totpAlgorithm: isTotpAlgorithm(value.totpAlgorithm) ? value.totpAlgorithm : undefined,
      totpDigits: value.totpDigits === 6 || value.totpDigits === 8 ? value.totpDigits : undefined,
      totpPeriod: typeof value.totpPeriod === 'number' ? value.totpPeriod : undefined,
      customFields: isStringRecord(value.customFields) ? value.customFields : undefined,
    };
  } catch {
    return null;
  }
}

export function parseOpLogCategoryPlaintext(record: LocalVerifiedRecord): CategorySummary | null {
  if (!isVerifiedRecord(record) || record.record.recordType !== 'category' || !record.plaintext) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const value = parsed as Record<string, unknown>;
    return {
      id: record.record.recordId,
      name: typeof value.name === 'string' && value.name.trim() ? value.name : 'Kategorie',
    };
  } catch {
    return null;
  }
}

/**
 * Reads the raw verified plaintext as an object map.
 *
 * Used when the list edits a single field and needs to forward the remaining
 * plaintext fields (e.g. sortOrder, customFields) unchanged on write.
 */
export function parseVerifiedPlaintextObject(
  record: LocalVerifiedRecord | null | undefined,
): Record<string, unknown> | null {
  if (!record?.plaintext) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

export function readOptionalSortOrder(value: unknown): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function mapOpLogRecordToVaultItem(record: LocalVerifiedRecord): VaultItem | null {
  const decryptedData = parseOpLogItemPlaintext(record);
  if (!decryptedData) {
    return null;
  }

  return {
    id: record.record.recordId,
    vault_id: record.record.vaultId,
    title: decryptedData.title ?? '',
    website_url: decryptedData.websiteUrl ?? null,
    icon_url: null,
    item_type: decryptedData.itemType ?? 'password',
    is_favorite: decryptedData.isFavorite ?? false,
    category_id: decryptedData.categoryId ?? null,
    created_at: record.record.createdAt,
    updated_at: record.record.updatedAt,
    decryptedData,
  };
}

/**
 * Builds the `ItemPlaintext` write payload from a UI `VaultItem`.
 *
 * `overrides` controls the only two fields the list mutates locally
 * (categoryRecordId, isFavorite); every other field is preserved from the
 * decrypted data and, where the cached UI item lacks coverage (sortOrder,
 * customFields), from the source verified plaintext. Returning `null` is the
 * contract for "no decrypted data available" so callers can skip the write
 * instead of silently overwriting plaintext with empty values.
 */
export function itemPlaintextFromVaultItem(
  item: VaultItem,
  overrides: Partial<Pick<ItemPlaintext, 'categoryRecordId' | 'isFavorite'>>,
  sourcePlaintext?: Record<string, unknown> | null,
): ItemPlaintext | null {
  const data = item.decryptedData;
  if (!data) {
    return null;
  }
  const sourceCustomFields = sourcePlaintext?.customFields;

  return {
    title: data.title ?? item.title ?? '',
    websiteUrl: data.websiteUrl ?? item.website_url ?? null,
    username: data.username ?? null,
    password: data.password ?? null,
    notes: data.notes ?? null,
    itemType: data.itemType === 'note'
      ? 'note'
      : data.itemType === 'totp'
        ? 'totp'
        : data.itemType === 'card'
          ? 'card'
          : 'password',
    categoryRecordId: overrides.categoryRecordId ?? data.categoryId ?? item.category_id ?? null,
    isFavorite: overrides.isFavorite ?? data.isFavorite ?? item.is_favorite ?? false,
    sortOrder: readOptionalSortOrder(sourcePlaintext?.sortOrder),
    totpSecret: data.totpSecret ?? null,
    totpIssuer: data.totpIssuer ?? null,
    totpLabel: data.totpLabel ?? null,
    totpAlgorithm: data.totpAlgorithm ?? null,
    totpDigits: data.totpDigits ?? null,
    totpPeriod: data.totpPeriod ?? null,
    customFields: data.customFields ?? (sourceCustomFields === null
      ? null
      : isStringRecord(sourceCustomFields)
        ? sourceCustomFields
        : null),
  };
}
