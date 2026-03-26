// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Shared create-mode configuration helpers for VaultItemDialog.
 */

export type VaultItemType = 'password' | 'note' | 'totp';

const ALL_ITEM_TYPES: VaultItemType[] = ['password', 'note', 'totp'];

/**
 * Resolve the list of createable item types for a dialog instance.
 *
 * @param allowedTypes Optional allow-list from the caller.
 * @returns Stable create-mode type order filtered to the allow-list.
 */
export function getAllowedCreateTypes(allowedTypes?: VaultItemType[]): VaultItemType[] {
    if (!allowedTypes || allowedTypes.length === 0) {
        return ALL_ITEM_TYPES;
    }

    return ALL_ITEM_TYPES.filter((type) => allowedTypes.includes(type));
}

/**
 * Compute the initial create type for the next dialog open.
 *
 * @param initialType Preferred starting type from the caller.
 * @param configuredTypes Allowed types for the dialog instance.
 * @param canUseTotp Whether the current user can access built-in TOTP.
 * @returns The first valid create type for the current dialog open.
 */
export function resolveInitialCreateType(
    initialType: VaultItemType,
    configuredTypes: VaultItemType[],
    canUseTotp: boolean,
): VaultItemType {
    const accessibleTypes = configuredTypes.filter((type) => type !== 'totp' || canUseTotp);
    const preferredType = initialType === 'totp' && !canUseTotp ? 'password' : initialType;

    if (accessibleTypes.includes(preferredType)) {
        return preferredType;
    }

    if (accessibleTypes.length > 0) {
        return accessibleTypes[0];
    }

    if (configuredTypes.includes(preferredType)) {
        return preferredType;
    }

    return configuredTypes[0] || 'password';
}
