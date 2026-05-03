// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Cryptographically Secure Password Generator
 * 
 * Uses Web Crypto API's getRandomValues() for secure random generation.
 * Supports both random character passwords and passphrases.
 *
 * Passphrase generation uses the EFF Short Wordlist 2.0 (1,296 words).
 * 4 words = ~41.4 bits entropy, 5 words = ~51.7 bits, 6 words = ~62.0 bits.
 */

import { EFF_SHORT_WORDLIST } from '@/services/wordlists';

// Character sets for password generation
const CHARSETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

// Passphrase wordlist: EFF Short Wordlist 2.0 (1,296 words)
// Imported from dedicated wordlists module for maintainability.
const WORD_LIST = EFF_SHORT_WORDLIST;

export interface PasswordOptions {
    length: number;
    uppercase: boolean;
    lowercase: boolean;
    numbers: boolean;
    symbols: boolean;
}

export interface PassphraseOptions {
    wordCount: number;
    separator: string;
    capitalize: boolean;
    includeNumber: boolean;
}

/**
 * Generates a cryptographically secure random password
 * 
 * @param options - Password generation options
 * @returns Generated password string
 */
export function generatePassword(options: PasswordOptions): string {
    const { length, uppercase, lowercase, numbers, symbols } = options;

    // Build character pool
    let charset = '';
    const requiredChars: string[] = [];

    if (uppercase) {
        charset += CHARSETS.uppercase;
        requiredChars.push(getSecureRandomChar(CHARSETS.uppercase));
    }
    if (lowercase) {
        charset += CHARSETS.lowercase;
        requiredChars.push(getSecureRandomChar(CHARSETS.lowercase));
    }
    if (numbers) {
        charset += CHARSETS.numbers;
        requiredChars.push(getSecureRandomChar(CHARSETS.numbers));
    }
    if (symbols) {
        charset += CHARSETS.symbols;
        requiredChars.push(getSecureRandomChar(CHARSETS.symbols));
    }

    // Fallback to lowercase if nothing selected
    if (charset.length === 0) {
        charset = CHARSETS.lowercase;
    }

    // Generate remaining characters
    const remainingLength = Math.max(0, length - requiredChars.length);
    const randomChars: string[] = [];

    for (let i = 0; i < remainingLength; i++) {
        randomChars.push(getSecureRandomChar(charset));
    }

    // Combine and shuffle
    const allChars = [...requiredChars, ...randomChars];
    shuffleArray(allChars);

    return allChars.join('');
}

/**
 * Generates a passphrase using random words
 * 
 * @param options - Passphrase generation options
 * @returns Generated passphrase string
 */
export function generatePassphrase(options: PassphraseOptions): string {
    const { wordCount, separator, capitalize, includeNumber } = options;

    const words: string[] = [];

    for (let i = 0; i < wordCount; i++) {
        let word = getSecureRandomElement(WORD_LIST);
        if (separator.length > 0 && word.includes(separator)) {
            word = word.split(separator).join('');
        }
        if (capitalize) {
            word = word.charAt(0).toUpperCase() + word.slice(1);
        }
        words.push(word);
    }

    let passphrase = words.join(separator);

    if (includeNumber) {
        const randomNum = getSecureRandomInt(100, 999);
        passphrase += separator + randomNum;
    }

    return passphrase;
}

/**
 * Calculates password strength/entropy
 * 
 * @param password - Password to analyze
 * @returns Strength object with score and label
 */
export function calculateStrength(password: string): PasswordStrength {
    let charsetSize = 0;

    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

    // Calculate entropy: log2(charsetSize^length)
    const entropy = password.length * Math.log2(charsetSize || 1);

    // Determine strength level
    let score: 0 | 1 | 2 | 3 | 4;
    let label: string;
    let color: string;

    if (entropy < 28) {
        score = 0;
        label = 'weak';
        color = 'bg-red-500';
    } else if (entropy < 36) {
        score = 1;
        label = 'fair';
        color = 'bg-orange-500';
    } else if (entropy < 60) {
        score = 2;
        label = 'good';
        color = 'bg-yellow-500';
    } else if (entropy < 80) {
        score = 3;
        label = 'strong';
        color = 'bg-green-500';
    } else {
        score = 4;
        label = 'veryStrong';
        color = 'bg-emerald-500';
    }

    return {
        score,
        label,
        color,
        entropy: Math.round(entropy),
    };
}

/**
 * Default password options
 */
export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
    length: 16,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
};

/**
 * Default passphrase options
 */
export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
    wordCount: 4,
    separator: '-',
    capitalize: true,
    includeNumber: true,
};

// ============ Helper Functions ============

/**
 * Gets a cryptographically secure random character from a string
 */
function getSecureRandomChar(str: string): string {
    const randomIndex = getSecureRandomInt(0, str.length - 1);
    return str[randomIndex];
}

/**
 * Gets a cryptographically secure random element from an array
 */
function getSecureRandomElement<T>(arr: T[]): T {
    const randomIndex = getSecureRandomInt(0, arr.length - 1);
    return arr[randomIndex];
}

/**
 * Generates a cryptographically secure random integer in range [min, max]
 */
function getSecureRandomInt(min: number, max: number): number {
    const range = max - min + 1;
    const bytesNeeded = Math.ceil(Math.log2(range) / 8) || 1;
    const maxValid = Math.floor((256 ** bytesNeeded) / range) * range - 1;

    let randomValue: number;
    const randomBytes = new Uint8Array(bytesNeeded);

    do {
        crypto.getRandomValues(randomBytes);
        randomValue = 0;
        for (let i = 0; i < bytesNeeded; i++) {
            randomValue = (randomValue << 8) | randomBytes[i];
        }
    } while (randomValue > maxValid);

    return min + (randomValue % range);
}

/**
 * Fisher-Yates shuffle using secure random
 */
function shuffleArray<T>(array: T[]): void {
    for (let i = array.length - 1; i > 0; i--) {
        const j = getSecureRandomInt(0, i);
        [array[i], array[j]] = [array[j], array[i]];
    }
}

// ============ Type Definitions ============

export interface PasswordStrength {
    score: 0 | 1 | 2 | 3 | 4;
    label: string;
    color: string;
    entropy: number;
}
