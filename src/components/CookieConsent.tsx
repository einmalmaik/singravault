// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Cookie consent wrapper that coordinates banner visibility,
 * settings dialog state, and backwards-compatible localStorage persistence.
 */

import { useEffect, useState } from 'react';

import { CookieBanner } from '@/components/CookieBanner';
import { CookieSettingsDialog } from '@/components/CookieSettingsDialog';

const CONSENT_STORAGE_KEY = 'singra-cookie-consent';
const BANNER_ENTER_DELAY_MS = 80;
const BANNER_EXIT_DELAY_MS = 250;

interface CookieConsentProps {
    variant?: 'default' | 'minimal';
}

export function CookieConsent({ variant: _variant = 'default' }: CookieConsentProps) {
    const [isBannerVisible, setIsBannerVisible] = useState(false);
    const [isBannerMounted, setIsBannerMounted] = useState(false);
    const [isSettingsOpen, setIsSettingsOpen] = useState(false);
    const [optional, setOptional] = useState(false);

    useEffect(() => {
        const consent = readConsent();
        if (!consent) {
            setIsBannerMounted(true);
            const timer = window.setTimeout(() => setIsBannerVisible(true), BANNER_ENTER_DELAY_MS);
            return () => window.clearTimeout(timer);
        }

        setOptional(consent.optional === true);
    }, []);

    useEffect(() => {
        const handleOpenSettings = () => {
            const consent = readConsent();
            if (consent) {
                setOptional(consent.optional === true);
            }
            setIsSettingsOpen(true);
        };

        window.addEventListener('singra:open-cookie-settings', handleOpenSettings);
        return () => window.removeEventListener('singra:open-cookie-settings', handleOpenSettings);
    }, []);

    const dismissBanner = () => {
        setIsBannerVisible(false);
        window.setTimeout(() => setIsBannerMounted(false), BANNER_EXIT_DELAY_MS);
    };

    const handleAcceptAll = () => {
        saveConsent({ optional: true });
        setOptional(true);
        dismissBanner();
    };

    const handleEssentialOnly = () => {
        saveConsent({ optional: false });
        setOptional(false);
        dismissBanner();
    };

    const handleCustomize = () => {
        setIsSettingsOpen(true);
    };

    const handleSettingsOpenChange = (open: boolean) => {
        if (open) {
            const consent = readConsent();
            if (consent) {
                setOptional(consent.optional === true);
            }
        }

        setIsSettingsOpen(open);
    };

    const handleSaveSettings = () => {
        saveConsent({ optional });
        setIsSettingsOpen(false);

        if (isBannerMounted) {
            dismissBanner();
        }
    };

    if (!isBannerMounted && !isSettingsOpen) {
        return null;
    }

    return (
        <>
            <CookieBanner
                visible={isBannerMounted}
                isActive={isBannerVisible}
                onAcceptAll={handleAcceptAll}
                onEssentialOnly={handleEssentialOnly}
                onCustomize={handleCustomize}
            />
            <CookieSettingsDialog
                open={isSettingsOpen}
                optional={optional}
                onOpenChange={handleSettingsOpenChange}
                onOptionalChange={setOptional}
                onSave={handleSaveSettings}
            />
        </>
    );
}

function readConsent(): StoredConsent | null {
    try {
        const stored = localStorage.getItem(CONSENT_STORAGE_KEY);
        if (!stored) {
            return null;
        }

        const parsed = JSON.parse(stored) as StoredConsent;
        if (typeof parsed !== 'object' || parsed === null) {
            return null;
        }

        if (parsed.necessary !== true || typeof parsed.optional !== 'boolean') {
            return null;
        }

        return parsed;
    } catch {
        return null;
    }
}

function saveConsent({ optional }: SaveConsentInput): void {
    localStorage.setItem(
        CONSENT_STORAGE_KEY,
        JSON.stringify({
            necessary: true,
            optional,
            analytics: false,
            timestamp: new Date().toISOString(),
        } satisfies StoredConsent),
    );
}

// ============ Type Definitions ============

interface StoredConsent {
    necessary: true;
    optional: boolean;
    analytics?: boolean;
    timestamp?: string;
}

interface SaveConsentInput {
    optional: boolean;
}
