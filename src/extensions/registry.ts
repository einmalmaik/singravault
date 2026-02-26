// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Extension Registry
 *
 * Central registry for premium plugin components, routes, and service hooks.
 * The Core defines slots; the premium package registers into them.
 * If no premium package is installed, slots remain empty — no crashes.
 */

import type { ComponentType } from 'react';
import type { ExtensionSlot, ExtensionComponent, ExtensionRoute, ServiceHooks } from './types';

// ============ Internal State ============

const componentRegistry = new Map<ExtensionSlot, ExtensionComponent>();
const routeRegistry: ExtensionRoute[] = [];
const serviceHooks: Partial<ServiceHooks> = {};

// ============ Component Registration ============

/**
 * Register a component into a named slot.
 *
 * @param slot - The slot identifier (e.g. 'settings.family')
 * @param component - The React component to render in that slot
 */
export function registerExtension(slot: ExtensionSlot, component: ExtensionComponent): void {
    if (componentRegistry.has(slot)) {
        console.warn(`[ExtensionRegistry] Slot "${slot}" is being overwritten.`);
    }
    componentRegistry.set(slot, component);
}

/**
 * Get the component registered for a slot, or null if none.
 *
 * @param slot - The slot identifier
 * @returns The registered component, or null
 */
export function getExtension<P = any>(slot: ExtensionSlot): ComponentType<P> | null {
    return (componentRegistry.get(slot) as ComponentType<P>) ?? null;
}

/**
 * Check whether a slot has a registered component.
 *
 * @param slot - The slot identifier
 * @returns true if a component is registered
 */
export function hasExtension(slot: ExtensionSlot): boolean {
    return componentRegistry.has(slot);
}

// ============ Route Registration ============

/**
 * Register a premium route.
 *
 * @param route - Route definition with path, component, and protection flag
 */
export function registerRoute(route: ExtensionRoute): void {
    const existing = routeRegistry.findIndex((r) => r.path === route.path);
    if (existing !== -1) {
        console.warn(`[ExtensionRegistry] Route "${route.path}" is being overwritten.`);
        routeRegistry[existing] = route;
    } else {
        routeRegistry.push(route);
    }
}

/**
 * Get all registered premium routes.
 *
 * @returns Array of route definitions
 */
export function getExtensionRoutes(): ReadonlyArray<ExtensionRoute> {
    return routeRegistry;
}

// ============ Service Hooks ============

/**
 * Register one or more service hooks from the premium package.
 * Service hooks inject business logic (e.g. duress, subscription)
 * into core components without requiring direct imports.
 *
 * @param hooks - Partial set of service hooks to register
 */
export function registerServiceHooks(hooks: Partial<ServiceHooks>): void {
    Object.assign(serviceHooks, hooks);
}

/**
 * Get the registered service hooks.
 * Returns the hooks object — callers check for undefined before calling.
 *
 * @returns The service hooks (some may be undefined if premium is not installed)
 */
export function getServiceHooks(): Readonly<Partial<ServiceHooks>> {
    return serviceHooks;
}

// ============ Utilities ============

/**
 * Check whether the premium package has been loaded.
 * Returns true if any component, route, or service hook is registered.
 *
 * @returns true if premium extensions are active
 */
export function isPremiumActive(): boolean {
    return componentRegistry.size > 0 || routeRegistry.length > 0 || Object.keys(serviceHooks).length > 0;
}

/**
 * Clear all registrations. Intended for testing only.
 */
export function clearRegistry(): void {
    componentRegistry.clear();
    routeRegistry.length = 0;
    for (const key of Object.keys(serviceHooks) as Array<keyof ServiceHooks>) {
        delete serviceHooks[key];
    }
}
