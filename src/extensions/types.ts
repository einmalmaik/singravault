// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Extension Slot Type Definitions
 *
 * Defines all named slots where premium components can be registered,
 * as well as service hook types for premium business logic.
 */

import type { ComponentType, ReactNode } from 'react';

import type { FeatureAccessContext, SubscriptionSnapshot } from '@/subscription/types';

// ============ Settings Sections ============

/** Settings surfaces exposed by the core shell. */
export type SettingsSurface = 'profile' | 'vault';

/** Canonical tabs available across settings surfaces. */
export type SettingsTabId =
    | 'general'
    | 'security'
    | 'billing-support'
    | 'data'
    | 'data-legal'
    | 'sharing-emergency';

/** Shared props exposed to registered settings section renderers. */
export interface SettingsSectionRenderProps {
    bypassFeatureGate?: boolean;
}

/**
 * Descriptor for a settings section contributed by core or premium.
 * The shell controls ordering, searchability, and tab grouping; the
 * renderer stays local to the owning package.
 */
export interface SettingsSectionDescriptor {
    id: string;
    surface: SettingsSurface;
    tab: SettingsTabId;
    order: number;
    title: string;
    keywords: string[];
    render: (props: SettingsSectionRenderProps) => ReactNode;
}

// ============ Page Slots ============

/** Slots for full premium pages */
export type PageSlot =
    | 'page.pricing'
    | 'page.vault-health'
    | 'page.authenticator'
    | 'page.grantor-vault';

// ============ Component Slots ============

/** Slots for inline premium components */
export type ComponentSlot =
    | 'landing.after-hero'
    | 'vault.file-attachments'
    | 'vault.pending-invitations'
    | 'subscription.feature-gate'
    | 'subscription.checkout-dialog'
    | 'layout.support-widget';

// ============ Combined Slot Type ============

/** All available extension slots */
export type ExtensionSlot = PageSlot | ComponentSlot;

// ============ Extension Component Types ============

/** A registered extension component. */
export type ExtensionComponent = ComponentType<unknown>;

// ============ Route Registration ============

/** A route registered by the premium package */
export interface ExtensionRoute {
    path: string;
    component: ComponentType<unknown>;
    /** Whether the route requires authentication */
    protected?: boolean;
    /** Whether the route requires an unlocked vault key in memory */
    requiresVaultUnlock?: boolean;
}

// ============ Service Hook Types ============

/**
 * Duress (panic password) configuration returned by the premium service.
 */
export interface DuressConfigHook {
    enabled: boolean;
    salt: string;
    verifier: string;
    kdfVersion: number;
}

/**
 * Result of a dual-unlock attempt (real vs duress password).
 */
export interface DualUnlockResult {
    mode: 'real' | 'duress' | 'invalid';
    key: CryptoKey | null;
}

/**
 * Minimal vault item structure needed for integrity checks.
 */
export interface VaultItemForIntegrity {
    id: string;
    encrypted_data: string;
}

/**
 * Result of an integrity verification run.
 */
export interface IntegrityVerificationResult {
    valid: boolean;
    isFirstCheck: boolean;
    computedRoot: string;
    storedRoot?: string;
    itemCount: number;
}

/**
 * Service hooks that premium can register to inject business logic
 * into the core without direct imports.
 */
export interface ServiceHooks {
    /**
     * Load the duress configuration for a user.
     * Returns null if duress is not configured.
     */
    getDuressConfig?: (userId: string) => Promise<DuressConfigHook | null>;

    /**
     * Attempt dual unlock with both real and duress passwords.
     */
    attemptDualUnlock?: (
        password: string,
        salt: string,
        verifier: string,
        kdfVersion: number,
        duressConfig: DuressConfigHook,
    ) => Promise<DualUnlockResult>;

    /**
     * Mark a vault item as a decoy item (duress mode).
     */
    markAsDecoyItem?: <T extends Record<string, unknown>>(itemData: T) => T;

    /**
     * Check if a decrypted vault item is a decoy (duress mode).
     * Returns false if duress is not configured / premium not installed.
     */
    isDecoyItem?: (decryptedData: Record<string, unknown>) => boolean;

    /**
     * Load subscription data for the current user.
     * Returns null if no subscription found.
     */
    getSubscription?: () => Promise<SubscriptionSnapshot | null>;

    /**
     * Evaluate whether a feature is available for the current subscription state.
     */
    hasFeatureAccess?: (feature: string, context: FeatureAccessContext) => boolean;

    /**
     * Return the minimum tier label for a feature gate prompt.
     */
    getRequiredTier?: (feature: string) => string;

    /**
     * Resolve the pricing entry path registered by the premium package.
     */
    getPricingEntryPath?: () => string;

    /**
     * Resolve the admin entry path registered by the premium package.
     */
    getAdminEntryPath?: () => string;

    /**
     * Load the current user's team access (roles + permissions).
     * Returns null if the user has no team access or admin is not installed.
     */
    getTeamAccess?: () => Promise<{ access: TeamAccessHook | null; error: Error | null }>;

    /**
     * Resolve whether the current user receives non-billing feature overrides.
     * This keeps the core feature gate generic and independent from admin logic.
     */
    getFeatureAccessOverride?: () => Promise<{ hasFullAccess: boolean }>;

    /**
     * Derive an integrity key for tamper detection.
     */
    deriveIntegrityKey?: (masterPassword: string, saltBase64: string) => Promise<CryptoKey>;

    /**
     * Verify vault item integrity against the stored root.
     */
    verifyVaultIntegrity?: (
        items: VaultItemForIntegrity[],
        integrityKey: CryptoKey,
        userId: string,
    ) => Promise<IntegrityVerificationResult>;

    /**
     * Update the stored integrity root after vault mutations.
     */
    updateIntegrityRoot?: (
        items: VaultItemForIntegrity[],
        integrityKey: CryptoKey,
        userId: string,
    ) => Promise<string>;

    /**
     * Clear the local integrity baseline for a user.
     */
    clearIntegrityRoot?: (userId: string) => void;
}

/**
 * Minimal team access shape returned by the premium admin service.
 */
export interface TeamAccessHook {
    roles: string[];
    permissions: string[];
    is_admin: boolean;
    can_access_admin: boolean;
    has_internal_role?: boolean;
    missing_admin_permissions?: string[];
}

/** Named service hook keys */
export type ServiceHookName = keyof ServiceHooks;
