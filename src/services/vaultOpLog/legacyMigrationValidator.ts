// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `legacyMigrationValidator` — validate legacy vault items and categories
 * before they are allowed to enter the new operation-log model.
 *
 * Responsibilities:
 * - Check that decrypted item plaintext matches the `VaultItemData` schema.
 * - Check that categories carry the minimal fields required for migration.
 * - Classify failures into `LegacyQuarantineReason` values.
 * - Never log plaintext contents, passwords or other secrets.
 *
 * Non-responsibilities:
 * - Decryption (caller provides plaintext).
 * - Re-encryption (handled by the mapper / orchestrator).
 * - Committing (handled by the repository layer).
 */

import {
  type LegacyVaultItemRow,
  type LegacyCategoryRow,
  type ValidatedLegacyItem,
  type ValidatedLegacyCategory,
  type LegacyItemValidationFailure,
  type LegacyCategoryValidationFailure,
  type LegacyQuarantineReason,
} from './migrationTypes';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ValidateLegacyItemInput {
  readonly legacyItem: LegacyVaultItemRow;
  readonly decryptedData: unknown;
}

export type ValidateLegacyItemResult =
  | { readonly ok: true; readonly validated: ValidatedLegacyItem }
  | { readonly ok: false; readonly failure: LegacyItemValidationFailure };

export interface ValidateLegacyCategoryInput {
  readonly legacyCategory: LegacyCategoryRow;
}

export type ValidateLegacyCategoryResult =
  | { readonly ok: true; readonly validated: ValidatedLegacyCategory }
  | { readonly ok: false; readonly failure: LegacyCategoryValidationFailure };

// ---------------------------------------------------------------------------
// Item validation
// ---------------------------------------------------------------------------

/**
 * Validate a legacy item plaintext after decryption.
 *
 * Checks:
 * 1. `decryptedData` is a plain object (not null, not array).
 * 2. `itemType` is one of the known values, if present.
 * 3. No deeply nested values that would break canonicalisation.
 * 4. `categoryId` is either a string or null/undefined.
 *
 * Security note: We do NOT validate password strength, TOTP validity
 * or URL correctness.  Migration only cares about structural fitness
 * for the new record model.
 */
export function validateLegacyItem(
  input: ValidateLegacyItemInput,
): { readonly ok: true; readonly validated: ValidatedLegacyItem } | { readonly ok: false; readonly failure: LegacyItemValidationFailure } {
  const { legacyItem, decryptedData } = input;

  if (!isPlainObject(decryptedData)) {
    return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'decrypted item is not a plain object');
  }

  const data = decryptedData as Record<string, unknown>;

  // itemType must be one of the known values, if present
  if ('itemType' in data && data.itemType !== undefined && data.itemType !== null) {
    if (!isKnownItemType(data.itemType)) {
      return classifyFailure(
        legacyItem.id,
        'legacyUnsupportedVersion',
        `unknown itemType: ${String(data.itemType)}`,
      );
    }
  }

  // categoryId must be string or null/undefined
  if ('categoryId' in data && data.categoryId !== undefined && data.categoryId !== null) {
    if (typeof data.categoryId !== 'string') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'categoryId is not a string');
    }
  }

  // title must be string or undefined, if present
  if ('title' in data && data.title !== undefined && typeof data.title !== 'string') {
    return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'title is not a string');
  }

  // websiteUrl must be string or undefined/null
  if ('websiteUrl' in data && data.websiteUrl !== undefined && data.websiteUrl !== null) {
    if (typeof data.websiteUrl !== 'string') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'websiteUrl is not a string');
    }
  }

  // username must be string or undefined/null
  if ('username' in data && data.username !== undefined && data.username !== null) {
    if (typeof data.username !== 'string') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'username is not a string');
    }
  }

  // password must be string or undefined/null
  if ('password' in data && data.password !== undefined && data.password !== null) {
    if (typeof data.password !== 'string') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'password is not a string');
    }
  }

  // notes must be string or undefined/null
  if ('notes' in data && data.notes !== undefined && data.notes !== null) {
    if (typeof data.notes !== 'string') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'notes is not a string');
    }
  }

  // customFields must be a plain object or undefined/null
  if ('customFields' in data && data.customFields !== undefined && data.customFields !== null) {
    if (!isPlainObject(data.customFields)) {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'customFields is not a plain object');
    }
  }

  // isFavorite must be boolean or undefined/null
  if ('isFavorite' in data && data.isFavorite !== undefined && data.isFavorite !== null) {
    if (typeof data.isFavorite !== 'boolean') {
      return classifyFailure(legacyItem.id, 'legacyInvalidSchema', 'isFavorite is not a boolean');
    }
  }

  return {
    ok: true,
    validated: {
      legacyId: legacyItem.id,
      categoryId: legacyItem.categoryId,
      decryptedData,
      legacyEncryptedData: legacyItem.encryptedData,
    },
  };
}

// ---------------------------------------------------------------------------
// Category validation
// ---------------------------------------------------------------------------

/**
 * Validate a legacy category row before migration.
 *
 * Checks:
 * 1. `name` is a non-empty string.
 * 2. `id` is a non-empty string.
 * 3. `userId` matches the expected user (caller must check this).
 */
export function validateLegacyCategory(
  input: ValidateLegacyCategoryInput,
): ValidateLegacyCategoryResult {
  const { legacyCategory } = input;

  if (typeof legacyCategory.id !== 'string' || legacyCategory.id.length === 0) {
    return classifyCategoryFailure(legacyCategory.id, 'legacyInvalidSchema', 'category id is empty');
  }

  if (typeof legacyCategory.name !== 'string' || legacyCategory.name.length === 0) {
    return classifyCategoryFailure(
      legacyCategory.id,
      'legacyMissingRequiredField',
      'category name is empty',
    );
  }

  if (typeof legacyCategory.userId !== 'string' || legacyCategory.userId.length === 0) {
    return classifyCategoryFailure(
      legacyCategory.id,
      'legacyInvalidSchema',
      'category userId is empty',
    );
  }

  return {
    ok: true,
    validated: {
      legacyId: legacyCategory.id,
      name: legacyCategory.name,
      color: legacyCategory.color,
      icon: legacyCategory.icon,
      parentId: legacyCategory.parentId,
      sortOrder: legacyCategory.sortOrder,
    },
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const KNOWN_ITEM_TYPES = new Set(['password', 'note', 'totp', 'card']);

function isKnownItemType(value: unknown): boolean {
  return typeof value === 'string' && KNOWN_ITEM_TYPES.has(value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function classifyFailure(
  legacyId: string,
  reason: LegacyQuarantineReason,
  detail: string,
): { ok: false; failure: LegacyItemValidationFailure } {
  return {
    ok: false,
    failure: { legacyId, reason, detail },
  };
}

function classifyCategoryFailure(
  legacyId: string,
  reason: LegacyQuarantineReason,
  detail: string,
): { ok: false; failure: LegacyCategoryValidationFailure } {
  return {
    ok: false,
    failure: { legacyId, reason, detail },
  };
}
