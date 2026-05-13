// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Category icon allowlist.
 *
 * Category icons are stored as developer-approved registry IDs. Legacy emoji
 * payloads are mapped to registry IDs so old categories keep a sensible icon
 * without rendering arbitrary text, SVG, or HTML.
 */

import {
    CATEGORY_ICON_PRESET_IDS,
    CATEGORY_ICON_REGISTRY,
    LEGACY_CATEGORY_EMOJI_MAP,
} from '@/lib/icons/categoryIconRegistry';

export const CATEGORY_ICON_PRESETS = CATEGORY_ICON_PRESET_IDS;

export function normalizeCategoryIcon(icon: string | null | undefined): string | null {
    const trimmed = icon?.trim() ?? '';
    if (!trimmed) {
        return null;
    }

    if (Object.prototype.hasOwnProperty.call(CATEGORY_ICON_REGISTRY, trimmed)) {
        return trimmed;
    }

    return LEGACY_CATEGORY_EMOJI_MAP[trimmed] ?? null;
}

export function isAllowedCategoryIcon(icon: string | null | undefined): boolean {
    return normalizeCategoryIcon(icon) !== null;
}
