import { sha256Base64, stableStringify } from './canonicalJson';
import type { IntegrityDiagnostic, ServerVaultCategoryV2, VaultManifestV2 } from './types';

export async function computeCategoriesHashV2(categories: ServerVaultCategoryV2[]): Promise<string> {
  return sha256Base64(stableStringify(canonicalCategories(categories)));
}

export async function verifyCategoriesAgainstManifestV2(
  categories: ServerVaultCategoryV2[],
  manifest: VaultManifestV2,
): Promise<
  | { ok: true; categoriesHash: string; diagnostics: IntegrityDiagnostic[] }
  | { ok: false; categoriesHash: string; diagnostics: IntegrityDiagnostic[] }
> {
  const categoriesHash = await computeCategoriesHashV2(categories);
  if (categoriesHash !== manifest.categoriesHash) {
    return {
      ok: false,
      categoriesHash,
      diagnostics: [{
        code: 'category_structure_mismatch',
        message: 'Category structure hash does not match the authenticated manifest.',
        manifestRevision: manifest.manifestRevision,
        observedHashPrefix: categoriesHash.slice(0, 12),
      }],
    };
  }

  return { ok: true, categoriesHash, diagnostics: [] };
}

function canonicalCategories(categories: ServerVaultCategoryV2[]) {
  return [...categories]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((category) => ({
      id: canonicalText(category.id),
      user_id: canonicalText(category.user_id),
      name: canonicalText(category.name),
      icon: canonicalNullableText(category.icon),
      color: canonicalNullableText(category.color),
      parent_id: canonicalNullableText(category.parent_id),
      sort_order: typeof category.sort_order === 'number' ? category.sort_order : null,
    }));
}

function canonicalText(value: string): string {
  return value.normalize('NFC');
}

function canonicalNullableText(value: string | null | undefined): string | null {
  return typeof value === 'string' ? value.normalize('NFC') : null;
}
