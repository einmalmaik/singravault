// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview i18n Configuration for Singra Vault
 *
 * This module sets up internationalization using i18next and react-i18next.
 * Currently supports German (default) and English.
 */

import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import { hasOptionalCookieConsent } from '@/lib/cookieConsent';
import de from './locales/de.json';
import en from './locales/en.json';

function decodeMojibakeString(input: string): string {
  const hasMojibakeMarkers = input.includes('Ã') || input.includes('Â') || input.includes('â');
  if (!hasMojibakeMarkers) return input;

  let current = input;
  for (let i = 0; i < 3; i++) {
    try {
      const bytes = Uint8Array.from(Array.from(current).map((char) => char.charCodeAt(0) & 0xff));
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }

  return current;
}

function normalizeLocaleObject<T>(value: T): T {
  if (typeof value === 'string') {
    return decodeMojibakeString(value) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => normalizeLocaleObject(item)) as T;
  }

  if (value && typeof value === 'object') {
    const normalizedEntries = Object.entries(value).map(([key, nested]) => [
      key,
      normalizeLocaleObject(nested),
    ]);
    return Object.fromEntries(normalizedEntries) as T;
  }

  return value;
}

const normalizedDe = normalizeLocaleObject(de);
const normalizedEn = normalizeLocaleObject(en);

export const languages = {
  de: { name: 'Deutsch', flag: '\u{1F1E9}\u{1F1EA}' },
  en: { name: 'English', flag: '\u{1F1EC}\u{1F1E7}' },
} as const;

export type LanguageCode = keyof typeof languages;
export type LanguagePreference = 'system' | LanguageCode;

export const SYSTEM_LANGUAGE_PREFERENCE = 'system' as const;
export const LANGUAGE_STORAGE_KEY = 'Singra-language';
export const LANGUAGE_PREFERENCE_STORAGE_KEY = 'Singra-language-preference';

export function isLanguageCode(value: string): value is LanguageCode {
  return value in languages;
}

export function isLanguagePreference(value: string): value is LanguagePreference {
  return value === SYSTEM_LANGUAGE_PREFERENCE || isLanguageCode(value);
}

export function resolveSystemLanguage(): LanguageCode {
  if (typeof navigator !== 'undefined') {
    const candidates = [navigator.language, ...(navigator.languages ?? [])]
      .map((lang) => lang.split('-')[0])
      .filter(Boolean);
    const supported = candidates.find((lang): lang is LanguageCode => isLanguageCode(lang));
    if (supported) {
      return supported;
    }
  }

  return 'de';
}

export function getStoredLanguagePreference(): LanguagePreference {
  if (!hasOptionalCookieConsent()) {
    return SYSTEM_LANGUAGE_PREFERENCE;
  }

  const storedPreference = localStorage.getItem(LANGUAGE_PREFERENCE_STORAGE_KEY);
  if (storedPreference && isLanguagePreference(storedPreference)) {
    return storedPreference;
  }

  const legacyLanguage = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  if (legacyLanguage && isLanguageCode(legacyLanguage)) {
    return legacyLanguage;
  }

  return SYSTEM_LANGUAGE_PREFERENCE;
}

export function resolveLanguagePreference(preference: LanguagePreference): LanguageCode {
  return preference === SYSTEM_LANGUAGE_PREFERENCE ? resolveSystemLanguage() : preference;
}

const getInitialLanguage = (): LanguageCode => {
  return resolveLanguagePreference(getStoredLanguagePreference());
};

i18n
  .use(initReactI18next)
  .init({
    resources: {
      de: { translation: normalizedDe },
      en: { translation: normalizedEn },
    },
    lng: getInitialLanguage(),
    fallbackLng: 'de',
    interpolation: {
      escapeValue: false,
    },
    debug: import.meta.env.DEV,
  });

function persistLanguagePreference(preference: LanguagePreference): void {
  const consent = localStorage.getItem('singra-cookie-consent');
  if (consent) {
    try {
      const parsed = JSON.parse(consent);
      if (parsed.optional) {
        localStorage.setItem(LANGUAGE_PREFERENCE_STORAGE_KEY, preference);
        if (preference === SYSTEM_LANGUAGE_PREFERENCE) {
          localStorage.removeItem(LANGUAGE_STORAGE_KEY);
        } else {
          localStorage.setItem(LANGUAGE_STORAGE_KEY, preference);
        }
      }
    } catch {
      // If parse fails, err on safe side and don't save.
    }
  }
}

export const changeLanguagePreference = (preference: LanguagePreference) => {
  persistLanguagePreference(preference);
  i18n.changeLanguage(resolveLanguagePreference(preference));
};

export const changeLanguage = (lang: LanguageCode) => {
  changeLanguagePreference(lang);
};

export default i18n;
