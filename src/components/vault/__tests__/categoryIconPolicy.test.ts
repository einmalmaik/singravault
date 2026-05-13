// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';

import { CATEGORY_ICON_PRESETS, normalizeCategoryIcon } from '../categoryIconPolicy';

describe('categoryIconPolicy', () => {
    it('accepts only developer-approved category icon registry ids', () => {
        expect(CATEGORY_ICON_PRESETS.length).toBeGreaterThanOrEqual(100);
        expect(normalizeCategoryIcon(CATEGORY_ICON_PRESETS[0])).toBe(CATEGORY_ICON_PRESETS[0]);
        expect(normalizeCategoryIcon(` ${CATEGORY_ICON_PRESETS[1]} `)).toBe(CATEGORY_ICON_PRESETS[1]);
        expect(normalizeCategoryIcon('passkeys')).toBe('passkeys');
        expect(normalizeCategoryIcon('smartHome')).toBe('smartHome');
    });

    it('maps legacy emoji presets to controlled category icon ids', () => {
        expect(normalizeCategoryIcon('\u{1F510}')).toBe('security');
        expect(normalizeCategoryIcon('\u{1F4BB}')).toBe('development');
    });

    it('rejects SVG markup and arbitrary text icons', () => {
        expect(normalizeCategoryIcon('<svg onload="alert(1)"></svg>')).toBeNull();
        expect(normalizeCategoryIcon('custom-icon')).toBeNull();
        expect(normalizeCategoryIcon('')).toBeNull();
        expect(normalizeCategoryIcon(null)).toBeNull();
    });
});
