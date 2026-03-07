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

const getInitialLanguage = (): LanguageCode => {
  if (hasOptionalCookieConsent()) {
    const stored = localStorage.getItem('Singra-language');
    if (stored && stored in languages) {
      return stored as LanguageCode;
    }
  }

  const browserLang = navigator.language.split('-')[0];
  if (browserLang in languages) {
    return browserLang as LanguageCode;
  }

  return 'de';
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

export const changeLanguage = (lang: LanguageCode) => {
  const consent = localStorage.getItem('singra-cookie-consent');
  if (consent) {
    try {
      const parsed = JSON.parse(consent);
      if (parsed.optional) {
        localStorage.setItem('Singra-language', lang);
      }
    } catch {
      // If parse fails, err on safe side and don't save.
    }
  }

  i18n.changeLanguage(lang);
};

export default i18n;
