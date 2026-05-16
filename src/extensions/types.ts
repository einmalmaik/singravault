// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Extension Slot Type Definitions
 *
 * Defines all named slots where premium components can be registered,
 * as well as service hook types for premium business logic.
 */

import type { ComponentType, ReactNode } from 'react';
import type { Session, User } from '@supabase/supabase-js';

import type { FeatureAccessContext, SubscriptionSnapshot } from '@/subscription/types';

// ============ Settings Sections ============

/** Settings surfaces exposed by the core shell. */
export type SettingsSurface = 'profile' | 'vault';

/** Canonical tabs available across settings surfaces. */
export type SettingsTabId =
    | 'general'
    | 'security'
    | 'billing'
    | 'support'
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

/** Minimal auth state exposed by the host app to global premium slots. */
export interface HostAuthState {
    user: User | null;
    session: Session | null;
    authReady: boolean;
    isOfflineSession: boolean;
}

/** Props for the global support widget slot. */
export interface SupportWidgetExtensionProps {
    auth: HostAuthState;
}

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
 *
 * @deprecated The dual-unlock contract is incompatible with the USK
 * (User-Symmetric-Key) architecture: it verifies the master password against
 * the master-derived key, but `profiles.master_password_verifier` is bound to
 * the UserKey, not the master-derived key. Premium implementations MUST
 * migrate to `attemptDuressUnlockOnly`, which checks the duress credentials
 * only and lets the core perform the canonical USK-based master-password
 * verification.
 */
export interface DualUnlockResult {
    mode: 'real' | 'duress' | 'invalid';
    key: CryptoKey | null;
}

/**
 * Result of a duress-only unlock attempt.
 *
 * Premium implementations of `attemptDuressUnlockOnly` MUST NOT attempt to
 * verify the real master password. The core performs that check against the
 * USK-based verifier; mixing both checks here re-introduces the pre-USK bug
 * where the master-derived key cannot match a UserKey-based verifier.
 */
export interface DuressOnlyUnlockInput {
    password: string;
    duressConfig: DuressConfigHook;
}

export interface DuressOnlyUnlockResult {
    /** True iff the supplied password matched the duress credentials. */
    matched: boolean;
    /** Derived duress vault key on a positive match; null otherwise. */
    key: CryptoKey | null;
}

/**
 * Plaintext shape of a single ephemeral decoy entry shown in the duress vault.
 *
 * Decoys never leave memory: they are synthesised on every duress unlock by
 * the premium hook (`getDuressDecoyItems`) and rendered directly without
 * touching the database. That is intentional. Persisting decoys to
 * `vault_items` (the previous behaviour) leaked their presence into the
 * legacy table, which broke the OpLog migration gate and was a privacy
 * regression for users who never even enabled duress mode.
 *
 * The shape is deliberately a strict subset of the regular vault item
 * plaintext so the core list renderer can treat decoys like any other
 * password entry without a separate code path.
 */
export interface DuressDecoyItemPlaintext {
    title: string;
    username?: string;
    password?: string;
    websiteUrl?: string;
    notes?: string;
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

export interface VaultHealthAnalysisItem {
    id: string;
    title: string;
    password: string;
    itemType?: 'password' | 'note' | 'totp' | 'card';
    username?: string;
    websiteUrl?: string;
    updatedAt: string;
}

export interface VaultHealthSidebarSummary {
    status: 'healthy' | 'review' | 'critical';
    score: number;
    passwordItems: number;
    affectedItems: number;
    criticalItems: number;
    warningItems: number;
    stats: {
        weak: number;
        pwned: number;
        duplicate: number;
        old: number;
        reused: number;
        strong: number;
    };
}

export interface VaultHealthSidebarSummaryInput {
    score: number;
    passwordItems: number;
    affectedItems: number;
    criticalItems: number;
    warningItems: number;
    stats: VaultHealthSidebarSummary['stats'];
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
     *
     * @deprecated USK-incompatible. Implement `attemptDuressUnlockOnly`
     * instead; the core performs the real master-password check against the
     * USK-based verifier and only delegates the duress-credential check.
     * Implementations are still invoked as a fallback for legacy Premium
     * builds, but a `mode: 'invalid'` result is treated as "duress did not
     * match" and falls through to the canonical primary unlock path.
     */
    attemptDualUnlock?: (
        password: string,
        salt: string,
        verifier: string,
        kdfVersion: number,
        duressConfig: DuressConfigHook,
    ) => Promise<DualUnlockResult>;

    /**
     * Verify the entered password against the user's duress credentials only.
     *
     * Implementations MUST:
     *   - derive the duress key with `duressConfig.salt` and
     *     `duressConfig.kdfVersion`
     *   - compare it against `duressConfig.verifier` only
     *   - leave the real master-password check to the core (USK path)
     *
     * Returning `matched: true` opens the decoy/duress vault. Returning
     * `matched: false` (or throwing) lets the core fall through to the normal
     * USK-based master-password unlock.
     */
    attemptDuressUnlockOnly?: (
        input: DuressOnlyUnlockInput,
    ) => Promise<DuressOnlyUnlockResult>;

    /**
     * Returns a fresh batch of ephemeral decoy entries for the duress vault.
     *
     * Implementations MUST:
     *   - return a new randomised set on every call (the user expectation is
     *     "the panic vault looks slightly different every time")
     *   - return only plaintext (the core never encrypts or persists these)
     *   - never read or write `vault_items` / OpLog state
     *
     * The result is consumed exclusively by `synthesizeDuressVaultItems` in
     * the core, which wraps each entry into an in-memory `VaultItem`.
     * Returning an empty array is allowed and simply renders an empty
     * decoy vault — the core never falls back to legacy decoy rows.
     */
    getDuressDecoyItems?: () => DuressDecoyItemPlaintext[];

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

    analyzeVaultHealthSummary?: (input: VaultHealthSidebarSummaryInput) => VaultHealthSidebarSummary;
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
