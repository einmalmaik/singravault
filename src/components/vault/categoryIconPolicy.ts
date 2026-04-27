// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Category icon allowlist.
 *
 * Category icons are intentionally limited to developer-approved text
 * graphemes. User-supplied SVG/markup is never accepted or rendered.
 */

export const CATEGORY_ICON_PRESETS = [
    '\u{1F4C1}',
    '\u{1F4BC}',
    '\u{1F3E0}',
    '\u{1F4B3}',
    '\u{1F6D2}',
    '\u{1F3AE}',
    '\u{2708}\u{FE0F}',
    '\u{2764}\u{FE0F}',
    '\u{1F510}',
    '\u{1F3E6}',
    '\u{1F4E7}',
    '\u{1F4F1}',
    '\u{1F4BB}',
    '\u{1F9F0}',
    '\u{1F4DA}',
    '\u{1F3AC}',
    '\u{1F3B5}',
    '\u{1F3E5}',
    '\u{1F697}',
    '\u{1F381}',
    '\u{2601}\u{FE0F}',
    '\u{1F9FE}',
    '\u{1F3F7}\u{FE0F}',
    '\u{2B50}',
] as const;

const CATEGORY_ICON_PRESET_SET = new Set<string>(CATEGORY_ICON_PRESETS);

export function normalizeCategoryIcon(icon: string | null | undefined): string | null {
    const trimmed = icon?.trim() ?? '';
    return CATEGORY_ICON_PRESET_SET.has(trimmed) ? trimmed : null;
}

export function isAllowedCategoryIcon(icon: string | null | undefined): boolean {
    return normalizeCategoryIcon(icon) !== null;
}
