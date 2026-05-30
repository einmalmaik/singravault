import type { VaultItemData } from '@/services/cryptoService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { VaultIntegrityDecryptBlockedError } from '@/services/vaultQuarantineOrchestrator';
import type { VaultOpLogUiView } from '@/services/vaultOpLog/vaultOpLogUiAdapter';
import {
  getVerifiedRecordIdsForEgress,
  isVaultSecurityModeBlockingEgress,
} from '@/services/vaultOpLog/vaultDataEgressPolicy';
import type {
  CategoryPlaintext,
  ItemPlaintext,
} from '@/services/vaultOpLog/vaultOpLogCrudService';
import type {
  LocalVaultState,
  LocalVerifiedRecord,
} from '@/services/vaultOpLog/vaultStateMachine';

type ExportableVaultItemRow = {
  id: string;
  title: string;
  website_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean | null;
  category_id: string | null;
  encrypted_data: string;
  updated_at?: string | null;
};

export interface VaultExportPayload {
  version: string;
  mode: 'normal' | 'safe';
  exportedAt: string;
  itemCount: number;
  categoryCount?: number;
  quarantinedItems: QuarantinedVaultItem[];
  categories?: Array<{
    id: string;
    name: string;
    icon: string | null;
    color: string | null;
    sortOrder?: number | null;
  }>;
  items: Array<{
    id: string;
    title: string;
    website_url: string | null;
    item_type: 'password' | 'note' | 'totp' | 'card';
    is_favorite: boolean;
    category_id: string | null;
    updated_at: string | null;
    sortOrder?: number | null;
    data: VaultItemData;
  }>;
}

export interface VaultExportOptions {
  mode?: 'normal' | 'safe';
  quarantinedItems?: QuarantinedVaultItem[];
  /**
   * When present, export is allowlist-based: only these item IDs may be
   * decrypted and included. This is the OpLog Phase-10 path where "not
   * verified" must fail closed even when the record is not explicitly listed
   * as quarantined or conflicted.
   */
  allowedItemIds?: Set<string>;
  /**
   * Item IDs that must be excluded from the export regardless of
   * whether they are decryptable. This is used by the Phase 10
   * egress policy to block quarantined, pending, conflict, and
   * unknown-author records from leaving the vault.
   */
  excludedItemIds?: Set<string>;
}

export interface VaultImportActions {
  createCategory: (plaintext: CategoryPlaintext) => Promise<{ error: Error | null; recordId: string | null }>;
  createItem: (plaintext: ItemPlaintext) => Promise<{ error: Error | null; recordId: string | null }>;
}

export interface VaultImportResult {
  itemCount: number;
  categoryCount: number;
}

export class VaultExportBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultExportBlockedError';
  }
}

export class VaultImportPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VaultImportPayloadError';
  }
}

const textDecoder = new TextDecoder();
type VaultExportCategory = NonNullable<VaultExportPayload['categories']>[number];
type VaultExportItem = VaultExportPayload['items'][number];
type NormalizedImportCategory = { exportId: string; plaintext: CategoryPlaintext };
type NormalizedImportItem = { exportedCategoryId: string | null; plaintext: ItemPlaintext };

export async function buildVaultExportPayload(
  items: ExportableVaultItemRow[],
  decryptItem: (encryptedData: string, entryId?: string) => Promise<VaultItemData>,
  options?: VaultExportOptions,
): Promise<VaultExportPayload> {
  const quarantinedIds = new Set(options?.quarantinedItems?.map((q) => q.id) ?? []);
  const allowedIds = options?.allowedItemIds ?? null;
  const excludedIds = options?.excludedItemIds ?? new Set<string>();

  const eligibleItems = items.filter((item) => {
    if (allowedIds && !allowedIds.has(item.id)) {
      return false;
    }
    if (quarantinedIds.has(item.id)) {
      return false;
    }
    if (excludedIds.has(item.id)) {
      return false;
    }
    return true;
  });

  const decryptedItems = await Promise.all(
    eligibleItems.map(async (item) => {
      try {
        const decrypted = await decryptItem(item.encrypted_data, item.id);
        return {
          id: item.id,
          title: decrypted.title || item.title,
          website_url: decrypted.websiteUrl || item.website_url,
          item_type: decrypted.itemType || item.item_type || 'password',
          is_favorite: typeof decrypted.isFavorite === 'boolean'
            ? decrypted.isFavorite
            : !!item.is_favorite,
          category_id: decrypted.categoryId ?? item.category_id ?? null,
          updated_at: item.updated_at ?? null,
          data: decrypted,
        };
      } catch (error) {
        if (error instanceof VaultIntegrityDecryptBlockedError) {
          throw error;
        }
        return null;
      }
    }),
  );

  const validItems = decryptedItems.filter((item): item is NonNullable<typeof item> => item !== null);

  return {
    version: '1.1',
    mode: options?.mode ?? 'normal',
    exportedAt: new Date().toISOString(),
    itemCount: validItems.length,
    quarantinedItems: options?.quarantinedItems ?? [],
    items: validItems,
  };
}

export function buildVaultOpLogExportPayload(
  localVaultState: LocalVaultState,
  opLogUiView: VaultOpLogUiView,
): VaultExportPayload {
  if (isVaultSecurityModeBlockingEgress(opLogUiView.vaultSecurityMode)) {
    throw new VaultExportBlockedError('Export ist ohne verifizierten Tresor-Zustand nicht erlaubt.');
  }

  const allowedIds = getVerifiedRecordIdsForEgress(opLogUiView);
  if (!allowedIds) {
    throw new VaultExportBlockedError('OpLog-Zustand ist nicht verfügbar.');
  }

  const categories = Array.from(localVaultState.recordsById.values()).flatMap((record) => {
    if (!allowedIds.has(record.record.recordId) || !isActiveVerifiedRecord(record) || record.record.recordType !== 'category') {
      return [];
    }

    const plaintext = parsePlaintextObject(record);
    const name = readRequiredString(plaintext.name, 'category.name');
    return [{
      id: record.record.recordId,
      name,
      icon: readNullableString(plaintext.icon),
      color: readNullableString(plaintext.color),
      sortOrder: readOptionalNumber(plaintext.sortOrder) ?? null,
    }];
  });

  const items = Array.from(localVaultState.recordsById.values()).flatMap((record) => {
    if (!allowedIds.has(record.record.recordId) || !isActiveVerifiedRecord(record) || record.record.recordType !== 'item') {
      return [];
    }

    const plaintext = parsePlaintextObject(record);
    const data = vaultItemDataFromPlaintext(plaintext);
    const itemType = data.itemType ?? 'password';
    const categoryId = data.categoryId ?? null;

    return [{
      id: record.record.recordId,
      title: data.title ?? '',
      website_url: data.websiteUrl ?? null,
      item_type: itemType,
      is_favorite: data.isFavorite ?? false,
      category_id: categoryId,
      updated_at: record.record.updatedAt ?? null,
      sortOrder: readOptionalNumber(plaintext.sortOrder) ?? null,
      data,
    }];
  });

  return {
    version: '1.2',
    mode: 'normal',
    exportedAt: new Date().toISOString(),
    itemCount: items.length,
    categoryCount: categories.length,
    quarantinedItems: [],
    categories,
    items,
  };
}

export function parseVaultImportPayload(json: string): VaultExportPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new VaultImportPayloadError('Importdatei ist kein gültiges JSON.');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new VaultImportPayloadError('Importdatei hat kein gültiges Vault-Exportformat.');
  }

  const payload = parsed as Partial<VaultExportPayload>;
  if (!Array.isArray(payload.items)) {
    throw new VaultImportPayloadError('Importdatei enthält keine gültige Eintragsliste.');
  }
  if (payload.categories !== undefined && !Array.isArray(payload.categories)) {
    throw new VaultImportPayloadError('Importdatei enthält keine gültige Kategorieliste.');
  }

  return payload as VaultExportPayload;
}

export async function importVaultExportPayload(
  payload: VaultExportPayload,
  actions: VaultImportActions,
): Promise<VaultImportResult> {
  const categoryIdByExportId = new Map<string, string>();
  const categories = payload.categories ?? [];
  const normalizedCategories = categories.map((category, index) => normalizeImportCategory(category, index));
  const normalizedItems = payload.items.map((item, index) => normalizeImportItem(item, index));

  for (let index = 0; index < normalizedCategories.length; index += 1) {
    const category = normalizedCategories[index];
    const result = await actions.createCategory(category.plaintext);
    if (result.error || !result.recordId) {
      throw new VaultImportPayloadError(`Kategorie ${index + 1} konnte nicht importiert werden.`);
    }
    categoryIdByExportId.set(category.exportId, result.recordId);
  }

  for (let index = 0; index < normalizedItems.length; index += 1) {
    const item = normalizedItems[index];
    const result = await actions.createItem({
      ...item.plaintext,
      categoryRecordId: item.exportedCategoryId
        ? categoryIdByExportId.get(item.exportedCategoryId) ?? null
        : null,
    });
    if (result.error || !result.recordId) {
      throw new VaultImportPayloadError(`Eintrag ${index + 1} konnte nicht importiert werden.`);
    }
  }

  return {
    itemCount: payload.items.length,
    categoryCount: categories.length,
  };
}

function isActiveVerifiedRecord(record: LocalVerifiedRecord): boolean {
  return (record.recordState === 'verified' || record.recordState === 'restoredFromSnapshot')
    && !record.record.isTombstone;
}

function parsePlaintextObject(record: LocalVerifiedRecord): Record<string, unknown> {
  if (!record.plaintext || record.plaintext.length === 0) {
    throw new VaultImportPayloadError('Verifizierter Plaintext fehlt.');
  }

  try {
    const parsed = JSON.parse(textDecoder.decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('not_object');
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new VaultImportPayloadError('Verifizierter Plaintext hat kein gültiges Format.');
  }
}

function readRequiredString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new VaultImportPayloadError(`Importfeld ${field} fehlt.`);
  }
  return value;
}

function readNullableString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function hasOwnField(value: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, field);
}

function readOptionalNullableStringField(
  source: Record<string, unknown>,
  field: string,
): string | null {
  if (!hasOwnField(source, field) || source[field] === null || source[field] === undefined) {
    return null;
  }
  if (typeof source[field] !== 'string') {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keinen gültigen Textwert.`);
  }
  return source[field];
}

function readOptionalNumber(value: unknown): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function readOptionalNumberField(source: Record<string, unknown>, field: string): number | null {
  if (!hasOwnField(source, field) || source[field] === null || source[field] === undefined) {
    return null;
  }
  if (typeof source[field] !== 'number' || !Number.isFinite(source[field])) {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keinen gültigen Zahlenwert.`);
  }
  return source[field];
}

function readOptionalBooleanField(source: Record<string, unknown>, field: string): boolean | undefined {
  if (!hasOwnField(source, field) || source[field] === undefined) {
    return undefined;
  }
  if (typeof source[field] !== 'boolean') {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keinen gültigen Boolean-Wert.`);
  }
  return source[field];
}

function readItemType(value: unknown): VaultItemData['itemType'] {
  return value === 'note' || value === 'totp' || value === 'card' || value === 'password'
    ? value
    : undefined;
}

function readOptionalItemTypeField(source: Record<string, unknown>, field: string): VaultItemData['itemType'] {
  if (!hasOwnField(source, field) || source[field] === undefined) {
    return undefined;
  }
  const itemType = readItemType(source[field]);
  if (!itemType) {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keinen gültigen Eintragstyp.`);
  }
  return itemType;
}

function readTotpAlgorithm(value: unknown): VaultItemData['totpAlgorithm'] {
  return value === 'SHA1' || value === 'SHA256' || value === 'SHA512'
    ? value
    : undefined;
}

function readOptionalTotpAlgorithmField(source: Record<string, unknown>, field: string): VaultItemData['totpAlgorithm'] | null {
  if (!hasOwnField(source, field) || source[field] === undefined || source[field] === null) {
    return null;
  }
  const algorithm = readTotpAlgorithm(source[field]);
  if (!algorithm) {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keinen gültigen TOTP-Algorithmus.`);
  }
  return algorithm;
}

function readTotpDigits(value: unknown): VaultItemData['totpDigits'] {
  return value === 6 || value === 8 ? value : undefined;
}

function readOptionalTotpDigitsField(source: Record<string, unknown>, field: string): VaultItemData['totpDigits'] | null {
  if (!hasOwnField(source, field) || source[field] === undefined || source[field] === null) {
    return null;
  }
  const digits = readTotpDigits(source[field]);
  if (!digits) {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keine gültige TOTP-Stellenzahl.`);
  }
  return digits;
}

function readOptionalCustomFieldsField(
  source: Record<string, unknown>,
  field: string,
): Record<string, string> | null {
  if (!hasOwnField(source, field) || source[field] === undefined || source[field] === null) {
    return null;
  }

  const value = source[field];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new VaultImportPayloadError(`Importfeld ${field} hat keine gültigen benutzerdefinierten Felder.`);
  }

  const customFields: Record<string, string> = {};
  for (const [key, fieldValue] of Object.entries(value)) {
    if (typeof fieldValue !== 'string') {
      throw new VaultImportPayloadError(`Importfeld ${field} enthält einen ungültigen Feldwert.`);
    }
    customFields[key] = fieldValue;
  }
  return customFields;
}

function readCustomFields(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new VaultImportPayloadError('Importfeld customFields hat keine gültigen benutzerdefinierten Felder.');
  }

  const customFields: Record<string, string> = {};
  for (const [key, fieldValue] of Object.entries(value)) {
    if (typeof fieldValue !== 'string') {
      throw new VaultImportPayloadError('Importfeld customFields enthält einen ungültigen Feldwert.');
    }
    customFields[key] = fieldValue;
  }
  return customFields;
}

function vaultItemDataFromPlaintext(plaintext: Record<string, unknown>): VaultItemData {
  const title = readRequiredString(plaintext.title, 'item.title');
  const itemType = readOptionalItemTypeField(plaintext, 'itemType') ?? 'password';
  const categoryId = readNullableString(plaintext.categoryRecordId ?? plaintext.categoryId);
  const data: VaultItemData = {
    title,
    websiteUrl: readNullableString(plaintext.websiteUrl) ?? undefined,
    itemType,
    isFavorite: readOptionalBooleanField(plaintext, 'isFavorite') ?? false,
    categoryId,
    username: readNullableString(plaintext.username) ?? undefined,
    password: readNullableString(plaintext.password) ?? undefined,
    notes: readNullableString(plaintext.notes) ?? undefined,
    totpSecret: readNullableString(plaintext.totpSecret) ?? undefined,
    totpIssuer: readNullableString(plaintext.totpIssuer) ?? undefined,
    totpLabel: readNullableString(plaintext.totpLabel) ?? undefined,
    totpAlgorithm: readTotpAlgorithm(plaintext.totpAlgorithm),
    totpDigits: readTotpDigits(plaintext.totpDigits),
    totpPeriod: readOptionalNumber(plaintext.totpPeriod) ?? undefined,
    customFields: readCustomFields(plaintext.customFields),
  };

  return data;
}

function normalizeImportCategory(
  category: VaultExportCategory,
  index: number,
): NormalizedImportCategory {
  if (!category || typeof category !== 'object') {
    throw new VaultImportPayloadError(`Kategorie ${index + 1} hat kein gültiges Format.`);
  }

  const exportId = readRequiredString(category.id, `categories[${index}].id`);
  const name = readRequiredString(category.name, `categories[${index}].name`).trim();
  if (!name) {
    throw new VaultImportPayloadError(`Kategorie ${index + 1} hat keinen Namen.`);
  }

  return {
    exportId,
    plaintext: {
      name,
      icon: readNullableString(category.icon),
      color: readNullableString(category.color),
      parentCategoryRecordId: null,
      sortOrder: readOptionalNumber(category.sortOrder) ?? null,
    },
  };
}

function normalizeImportItem(
  item: VaultExportItem,
  index: number,
): NormalizedImportItem {
  if (!item || typeof item !== 'object') {
    throw new VaultImportPayloadError(`Eintrag ${index + 1} hat kein gültiges Format.`);
  }

  const data = item.data && typeof item.data === 'object' && !Array.isArray(item.data)
    ? item.data as Record<string, unknown>
    : {};
  const itemRecord = item as unknown as Record<string, unknown>;
  const itemType = readOptionalItemTypeField(data, 'itemType')
    ?? readOptionalItemTypeField(itemRecord, 'item_type')
    ?? 'password';
  const title = hasOwnField(data, 'title')
    ? readRequiredString(data.title, `items[${index}].data.title`)
    : readRequiredString(item.title, `items[${index}].title`);
  const exportedCategoryId = hasOwnField(data, 'categoryId')
    ? readOptionalNullableStringField(data, 'categoryId')
    : readOptionalNullableStringField(itemRecord, 'category_id');
  const sortOrder = readOptionalNumberField(itemRecord, 'sortOrder');
  const totpPeriod = readOptionalNumberField(data, 'totpPeriod');
  const customFields = readOptionalCustomFieldsField(data, 'customFields');

  return {
    exportedCategoryId,
    plaintext: {
      title,
      websiteUrl: hasOwnField(data, 'websiteUrl')
        ? readOptionalNullableStringField(data, 'websiteUrl')
        : readOptionalNullableStringField(itemRecord, 'website_url'),
      username: readOptionalNullableStringField(data, 'username'),
      password: readOptionalNullableStringField(data, 'password'),
      notes: readOptionalNullableStringField(data, 'notes'),
      itemType,
      categoryRecordId: null,
      isFavorite: readOptionalBooleanField(data, 'isFavorite')
        ?? readOptionalBooleanField(itemRecord, 'is_favorite')
        ?? false,
      sortOrder: sortOrder ?? null,
      totpSecret: readOptionalNullableStringField(data, 'totpSecret'),
      totpIssuer: readOptionalNullableStringField(data, 'totpIssuer'),
      totpLabel: readOptionalNullableStringField(data, 'totpLabel'),
      totpAlgorithm: readOptionalTotpAlgorithmField(data, 'totpAlgorithm'),
      totpDigits: readOptionalTotpDigitsField(data, 'totpDigits'),
      totpPeriod: totpPeriod ?? null,
      customFields: customFields ?? null,
    },
  };
}
