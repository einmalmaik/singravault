// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Plaintext Mapper
 *
 * Verified OpLog plaintext → `Category` / `ItemPlaintext` projections used by
 * the sidebar. Mirrors `vaultItemList/vaultItemPlaintextMapper.ts` but with
 * the sidebar's narrower needs: it only cares about the item's category id
 * for the per-category count and produces an `ItemPlaintext` round-trip when
 * the user drops an item onto a sidebar category.
 *
 * The mapper preserves all unrelated plaintext fields when writing so a
 * sidebar drop never silently drops totp/customFields data.
 */

import type { ItemPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';

import type { Category } from './vaultSidebarTypes';

function isVerifiedRecord(record: LocalVerifiedRecord): boolean {
  return record.recordState === 'verified' || record.recordState === 'restoredFromSnapshot';
}

export function parseVerifiedRecordPlaintext(record: LocalVerifiedRecord): Record<string, unknown> | null {
  if (!isVerifiedRecord(record) || !record.plaintext) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function getVerifiedItemCategoryId(record: LocalVerifiedRecord | null | undefined): string | null {
  if (!record || record.record.recordType !== 'item') {
    return null;
  }

  const plaintext = parseVerifiedRecordPlaintext(record);
  const categoryRecordId = plaintext?.categoryRecordId;
  return typeof categoryRecordId === 'string' ? categoryRecordId : null;
}

function readOptionalNumber(value: unknown): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function readCustomFields(value: unknown): Record<string, string> | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;

  const parsed: Record<string, string> = {};
  for (const [key, fieldValue] of Object.entries(value)) {
    if (typeof fieldValue !== 'string') {
      return undefined;
    }
    parsed[key] = fieldValue;
  }
  return parsed;
}

function hasPlaintextField(plaintext: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(plaintext, field);
}

/**
 * Builds an `ItemPlaintext` payload for the sidebar's drag-to-category drop.
 *
 * Returns `null` when the source plaintext is missing required fields or
 * when extension fields (sortOrder, customFields) are partially malformed.
 * The caller must skip the write in that case so we never overwrite a real
 * record with a half-valid payload.
 */
export function mapVerifiedItemRecordToPlaintext(
  record: LocalVerifiedRecord | null | undefined,
  nextCategoryRecordId: string | null,
): ItemPlaintext | null {
  if (!record || record.record.recordType !== 'item') {
    return null;
  }

  const plaintext = parseVerifiedRecordPlaintext(record);
  if (!plaintext) {
    return null;
  }
  const title = plaintext.title;
  const itemType = plaintext.itemType === 'note'
    ? 'note'
    : plaintext.itemType === 'totp'
      ? 'totp'
      : plaintext.itemType === 'card'
        ? 'card'
        : plaintext.itemType === 'password'
          ? 'password'
          : null;
  const sortOrder = readOptionalNumber(plaintext.sortOrder);
  const customFields = readCustomFields(plaintext.customFields);

  if (
    typeof title !== 'string'
    || !itemType
    || (hasPlaintextField(plaintext, 'sortOrder') && sortOrder === undefined)
    || (hasPlaintextField(plaintext, 'customFields') && customFields === undefined)
  ) {
    return null;
  }

  return {
    title,
    websiteUrl: typeof plaintext.websiteUrl === 'string' ? plaintext.websiteUrl : null,
    username: typeof plaintext.username === 'string' ? plaintext.username : null,
    password: typeof plaintext.password === 'string' ? plaintext.password : null,
    notes: typeof plaintext.notes === 'string' ? plaintext.notes : null,
    itemType,
    categoryRecordId: nextCategoryRecordId,
    isFavorite: typeof plaintext.isFavorite === 'boolean' ? plaintext.isFavorite : false,
    sortOrder: sortOrder ?? null,
    totpSecret: typeof plaintext.totpSecret === 'string' ? plaintext.totpSecret : null,
    totpIssuer: typeof plaintext.totpIssuer === 'string' ? plaintext.totpIssuer : null,
    totpLabel: typeof plaintext.totpLabel === 'string' ? plaintext.totpLabel : null,
    totpAlgorithm: plaintext.totpAlgorithm === 'SHA1' || plaintext.totpAlgorithm === 'SHA256' || plaintext.totpAlgorithm === 'SHA512'
      ? plaintext.totpAlgorithm
      : null,
    totpDigits: plaintext.totpDigits === 6 || plaintext.totpDigits === 8 ? plaintext.totpDigits : null,
    totpPeriod: typeof plaintext.totpPeriod === 'number' ? plaintext.totpPeriod : null,
    customFields: customFields ?? null,
  };
}

export function mapVerifiedCategoryRecord(record: LocalVerifiedRecord, count: number): Category | null {
  if (record.record.recordType !== 'category') {
    return null;
  }

  const plaintext = parseVerifiedRecordPlaintext(record);
  if (!plaintext) {
    return null;
  }

  const name = plaintext.name;
  return {
    id: record.record.recordId,
    name: typeof name === 'string' ? name : '',
    icon: typeof plaintext.icon === 'string' ? plaintext.icon : null,
    color: typeof plaintext.color === 'string' ? plaintext.color : null,
    count,
  };
}
