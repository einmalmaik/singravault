// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';

import { CATEGORY_ICON_PRESETS, normalizeCategoryIcon } from '../categoryIconPolicy';

describe('categoryIconPolicy', () => {
    it('accepts only developer-approved category icon presets', () => {
        expect(normalizeCategoryIcon(CATEGORY_ICON_PRESETS[0])).toBe(CATEGORY_ICON_PRESETS[0]);
        expect(normalizeCategoryIcon(` ${CATEGORY_ICON_PRESETS[1]} `)).toBe(CATEGORY_ICON_PRESETS[1]);
    });

    it('rejects SVG markup and arbitrary text icons', () => {
        expect(normalizeCategoryIcon('<svg onload="alert(1)"></svg>')).toBeNull();
        expect(normalizeCategoryIcon('custom-icon')).toBeNull();
        expect(normalizeCategoryIcon('')).toBeNull();
        expect(normalizeCategoryIcon(null)).toBeNull();
    });
});
