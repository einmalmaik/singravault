// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Premium Plugin Initializer
 *
 * Registers all premium components, routes, and service hooks
 * into the Core's Extension Registry. This file is the bridge
 * between the Core and the premium features that currently
 * live in this repo.
 *
 * When the code is split into separate repos, this file moves
 * to @singra/premium and is dynamically imported in main.tsx.
 */

import { registerExtension, registerRoute, registerServiceHooks } from '@/extensions/registry';

// Premium Settings Components
import { SubscriptionSettings } from '@/components/Subscription/SubscriptionSettings';
import EmergencyAccessSettings from '@/components/settings/EmergencyAccessSettings';
import { FamilyOrganizationSettings } from '@/components/settings/FamilyOrganizationSettings';
import { SharedCollectionsSettings } from '@/components/settings/SharedCollectionsSettings';
import { SupportWidget } from '@/components/SupportWidget';
import { FileAttachments } from '@/components/vault/FileAttachments';

// Premium Pages
import PricingPage from '@/pages/PricingPage';
import VaultHealthPage from '@/pages/VaultHealthPage';
import AuthenticatorPage from '@/pages/AuthenticatorPage';
import GrantorVaultPage from '@/pages/GrantorVaultPage';
import AdminPage from '@/pages/AdminPage';

// Premium Services (service hooks for core integration)
import { getDuressConfig, attemptDualUnlock, markAsDecoyItem, isDecoyItem } from '@/services/duressService';
import { getSubscription } from '@/services/subscriptionService';
import { getTeamAccess } from '@/services/adminService';

/**
 * Initialize all premium extensions.
 * Call this before rendering the App.
 */
export function initPremium(): void {
    // --- Settings Slots ---
    registerExtension('settings.subscription', SubscriptionSettings);
    registerExtension('settings.emergency', EmergencyAccessSettings);
    registerExtension('settings.family', FamilyOrganizationSettings);
    registerExtension('settings.shared-collections', SharedCollectionsSettings);

    // --- Component Slots ---
    registerExtension('layout.support-widget', SupportWidget);
    registerExtension('vault.file-attachments', FileAttachments);

    // --- Premium Routes ---
    registerRoute({ path: '/pricing', component: PricingPage, protected: false });
    registerRoute({ path: '/vault-health', component: VaultHealthPage, protected: true });
    registerRoute({ path: '/authenticator', component: AuthenticatorPage, protected: true });
    registerRoute({ path: '/vault/emergency/:id', component: GrantorVaultPage, protected: true });
    registerRoute({ path: '/admin', component: AdminPage, protected: true });

    // --- Service Hooks (inject premium logic into core) ---
    registerServiceHooks({
        getDuressConfig,
        attemptDualUnlock,
        markAsDecoyItem,
        isDecoyItem,
        getSubscription,
        getTeamAccess,
    });
}
