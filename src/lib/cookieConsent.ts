export const CONSENT_STORAGE_KEY = 'singra-cookie-consent';

const OPTIONAL_STORAGE_KEYS = ['Singra-language', 'i18nextLng', 'singra_autolock'] as const;
const LEGACY_SIDEBAR_COOKIE = 'sidebar:state';

export interface StoredCookieConsent {
    necessary: true;
    optional: boolean;
    analytics?: boolean;
    timestamp?: string;
}

interface SaveCookieConsentInput {
    optional: boolean;
}

const isStoredCookieConsent = (value: unknown): value is StoredCookieConsent => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const candidate = value as Partial<StoredCookieConsent>;
    return candidate.necessary === true && typeof candidate.optional === 'boolean';
};

export function readCookieConsent(): StoredCookieConsent | null {
    try {
        const stored = localStorage.getItem(CONSENT_STORAGE_KEY);
        if (!stored) {
            return null;
        }

        const parsed = JSON.parse(stored) as unknown;
        return isStoredCookieConsent(parsed) ? parsed : null;
    } catch {
        return null;
    }
}

export function saveCookieConsent({ optional }: SaveCookieConsentInput): StoredCookieConsent {
    const consent: StoredCookieConsent = {
        necessary: true,
        optional,
        analytics: false,
        timestamp: new Date().toISOString(),
    };

    localStorage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(consent));
    return consent;
}

export function hasOptionalCookieConsent(): boolean {
    return readCookieConsent()?.optional === true;
}

export function clearOptionalCookieData(): void {
    OPTIONAL_STORAGE_KEYS.forEach((key) => {
        localStorage.removeItem(key);
    });

    document.cookie = `${LEGACY_SIDEBAR_COOKIE}=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}
