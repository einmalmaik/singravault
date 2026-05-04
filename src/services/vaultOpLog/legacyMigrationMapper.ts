// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * `legacyMigrationMapper` — map validated legacy items and categories
 * into the new operation-log record model.
 *
 * Responsibilities:
 * - Build deterministic new record IDs from legacy IDs.
 * - Build category plaintexts for sealed category records.
 * - Build item plaintexts that embed the new category record ID.
 * - Produce canonicalised Uint8Array payloads ready for `sealRecord`.
 *
 * Non-responsibilities:
 * - Encryption (caller uses `cryptoRecordService.sealRecord`).
 * - Signing (caller uses `operationSigningService`).
 * - Commit (caller uses `vaultOpLogRepository`).
 *
 * Security note: Every plaintext is canonicalised before sealing so
 * that two clients produce identical bytes for the same logical
 * content.  No secrets are logged.
 */

import {
  canonicalizeVaultStructure,
} from './canonicalJson';
import {
  type ValidatedLegacyItem,
  type ValidatedLegacyCategory,
  type PreparedItemMigration,
  type PreparedCategoryMigration,
} from './migrationTypes';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface BuildMigratedCategoryPlaintextInput {
  readonly validatedCategory: ValidatedLegacyCategory;
  readonly newRecordId: string;
}

export interface BuildMigratedItemPlaintextInput {
  readonly validatedItem: ValidatedLegacyItem;
  readonly newRecordId: string;
  /**
   * The new category record ID that corresponds to the legacy
   * category referenced by the item.  `null` when the item had no
   * category or the category could not be migrated.
   */
  readonly mappedCategoryRecordId: string | null;
}

// ---------------------------------------------------------------------------
// Category plaintext builder
// ---------------------------------------------------------------------------

/**
 * Build a canonicalised plaintext for a migrated category record.
 *
 * Schema (v1):
 * ```ts
 * {
 *   name: string;
 *   color: string | null;
 *   icon: string | null;
 *   parentCategoryRecordId: string | null;
 *   sortOrder: number | null;
 *   migratedFromLegacyId: string;
 * }
 * ```
 */
export function buildMigratedCategoryPlaintext(
  input: BuildMigratedCategoryPlaintextInput,
): PreparedCategoryMigration {
  const { validatedCategory, newRecordId } = input;

  const payload = {
    name: validatedCategory.name,
    color: validatedCategory.color,
    icon: validatedCategory.icon,
    parentCategoryRecordId: validatedCategory.parentId, // will be remapped if parent also migrated
    sortOrder: validatedCategory.sortOrder,
    migratedFromLegacyId: validatedCategory.legacyId,
  };

  return {
    newRecordId,
    legacyId: validatedCategory.legacyId,
    plaintext: canonicalizeVaultStructure(payload),
  };
}

// ---------------------------------------------------------------------------
// Item plaintext builder
// ---------------------------------------------------------------------------

/**
 * Build a canonicalised plaintext for a migrated item record.
 *
 * Schema (v1):
 * ```ts
 * {
 *   title: string | undefined;
 *   websiteUrl: string | undefined;
 *   itemType: 'password' | 'note' | 'totp' | 'card' | undefined;
 *   isFavorite: boolean | undefined;
 *   categoryRecordId: string | null;
 *   username: string | undefined;
 *   password: string | undefined;
 *   notes: string | undefined;
 *   totpSecret: string | undefined;
 *   totpIssuer: string | undefined;
 *   totpLabel: string | undefined;
 *   totpAlgorithm: 'SHA1' | 'SHA256' | 'SHA512' | undefined;
 *   totpDigits: 6 | 8 | undefined;
 *   totpPeriod: number | undefined;
 *   customFields: Record<string, string> | undefined;
 *   migratedFromLegacyId: string;
 * }
 * ```
 *
 * The `categoryRecordId` field is the **new** record ID of the
 * migrated category, not the legacy category UUID.  This binds the
 * item to the new category record so that the encrypted plaintext
 * itself carries the relationship, satisfying the requirement that
 * category IDs live inside the encrypted item plaintext.
 */
export function buildMigratedItemPlaintext(
  input: BuildMigratedItemPlaintextInput,
): PreparedItemMigration {
  const { validatedItem, newRecordId, mappedCategoryRecordId } = input;

  const data = validatedItem.decryptedData as Record<string, unknown>;

  const payload: Record<string, unknown> = {
    title: data.title,
    websiteUrl: data.websiteUrl,
    itemType: data.itemType,
    isFavorite: data.isFavorite,
    categoryRecordId: mappedCategoryRecordId,
    username: data.username,
    password: data.password,
    notes: data.notes,
    totpSecret: data.totpSecret,
    totpIssuer: data.totpIssuer,
    totpLabel: data.totpLabel,
    totpAlgorithm: data.totpAlgorithm,
    totpDigits: data.totpDigits,
    totpPeriod: data.totpPeriod,
    customFields: data.customFields,
    migratedFromLegacyId: validatedItem.legacyId,
  };

  // Strip undefined values so canonicalisation is stable
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value !== undefined) {
      cleaned[key] = value;
    }
  }

  return {
    newRecordId,
    legacyId: validatedItem.legacyId,
    plaintext: canonicalizeVaultStructure(cleaned),
  };
}

// ---------------------------------------------------------------------------
// ID mapping
// ---------------------------------------------------------------------------

/**
 * Derive a deterministic new record ID from a legacy ID.
 *
 * The mapping must be stable so that retrying the migration does not
 * create duplicate records.  We prefix the legacy UUID with the
 * migration namespace so that collisions with genuinely new records
 * are impossible.
 */
export function legacyToNewRecordId(legacyId: string): string {
  return `mig-${legacyId}`;
}
