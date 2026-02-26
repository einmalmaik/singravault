// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Health Analysis Service
 *
 * Client-side password analysis engine that evaluates vault items
 * for weak, duplicate, old, and reused passwords.
 * All analysis happens locally — no data leaves the client.
 */

// ============ Types ============

export interface HealthIssue {
    itemId: string;
    title: string;
    type: 'weak' | 'duplicate' | 'old' | 'reused';
    severity: 'critical' | 'warning' | 'info';
    description: string;
}

export interface HealthReport {
    score: number; // 0–100
    totalItems: number;
    passwordItems: number;
    issues: HealthIssue[];
    stats: {
        weak: number;
        duplicate: number;
        old: number;
        reused: number;
        strong: number;
    };
}

export interface DecryptedPasswordItem {
    id: string;
    title: string;
    password: string;
    username?: string;
    websiteUrl?: string;
    updatedAt: string;
}

// ============ Analysis Functions ============

/**
 * Calculate password entropy in bits
 */
function calculateEntropy(password: string): number {
    const charsetSizes: { regex: RegExp; size: number }[] = [
        { regex: /[a-z]/, size: 26 },
        { regex: /[A-Z]/, size: 26 },
        { regex: /[0-9]/, size: 10 },
        { regex: /[^a-zA-Z0-9]/, size: 32 },
    ];

    let charsetSize = 0;
    for (const { regex, size } of charsetSizes) {
        if (regex.test(password)) {
            charsetSize += size;
        }
    }

    if (charsetSize === 0) return 0;
    return Math.floor(password.length * Math.log2(charsetSize));
}

/**
 * Check if a password is considered weak
 */
function isWeakPassword(password: string): { weak: boolean; reason: string } {
    if (password.length < 8) {
        return { weak: true, reason: 'too_short' };
    }

    const entropy = calculateEntropy(password);
    if (entropy < 28) {
        return { weak: true, reason: 'low_entropy' };
    }

    // Common patterns
    const commonPatterns = [
        /^[a-z]+$/i,            // all letters
        /^[0-9]+$/,             // all numbers
        /^(.)\1+$/,             // repeated character
        /^(012|123|234|345|456|567|678|789)/,
        /^(abc|bcd|cde|def|efg)/i,
        /password/i,
        /qwerty/i,
        /letmein/i,
        /welcome/i,
        /admin/i,
    ];

    for (const pattern of commonPatterns) {
        if (pattern.test(password)) {
            return { weak: true, reason: 'common_pattern' };
        }
    }

    if (password.length < 12 && entropy < 40) {
        return { weak: true, reason: 'moderate_entropy' };
    }

    return { weak: false, reason: '' };
}

/**
 * Check if a password is old (>90 days since last update)
 */
function isOldPassword(updatedAt: string): boolean {
    const ageMs = Date.now() - new Date(updatedAt).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    return ageDays > 90;
}

/**
 * Find duplicate passwords across items
 */
function findDuplicates(items: DecryptedPasswordItem[]): Map<string, string[]> {
    const passwordMap = new Map<string, string[]>();

    for (const item of items) {
        if (!item.password) continue;
        const existing = passwordMap.get(item.password) || [];
        existing.push(item.id);
        passwordMap.set(item.password, existing);
    }

    // Only return groups with 2+ items
    const duplicates = new Map<string, string[]>();
    for (const [pwd, ids] of passwordMap) {
        if (ids.length >= 2) {
            duplicates.set(pwd, ids);
        }
    }
    return duplicates;
}

// ============ Main Analysis ============

/**
 * Analyze all decrypted password items and generate a health report.
 * All processing happens client-side.
 */
export function analyzeVaultHealth(items: DecryptedPasswordItem[]): HealthReport {
    const issues: HealthIssue[] = [];
    const itemMap = new Map(items.map(i => [i.id, i]));
    const passwordItems = items.filter(i => i.password);
    let weakCount = 0;
    let duplicateCount = 0;
    let oldCount = 0;
    let reusedCount = 0;

    // 1. Check for weak passwords
    for (const item of passwordItems) {
        const { weak, reason } = isWeakPassword(item.password);
        if (weak) {
            weakCount++;
            issues.push({
                itemId: item.id,
                title: item.title,
                type: 'weak',
                severity: reason === 'too_short' || reason === 'common_pattern' ? 'critical' : 'warning',
                description: reason,
            });
        }
    }

    // 2. Check for duplicates
    const duplicates = findDuplicates(passwordItems);
    const seenDuplicateIds = new Set<string>();
    for (const [, ids] of duplicates) {
        for (const id of ids) {
            if (seenDuplicateIds.has(id)) continue;
            seenDuplicateIds.add(id);
            duplicateCount++;
            const item = itemMap.get(id)!;
            const otherTitles = ids
                .filter(otherId => otherId !== id)
                .map(otherId => itemMap.get(otherId)?.title || 'Unknown')
                .join(', ');
            issues.push({
                itemId: id,
                title: item.title,
                type: 'duplicate',
                severity: 'warning',
                description: otherTitles,
            });
        }
    }

    // 3. Check for old passwords
    for (const item of passwordItems) {
        if (isOldPassword(item.updatedAt)) {
            oldCount++;
            issues.push({
                itemId: item.id,
                title: item.title,
                type: 'old',
                severity: 'info',
                description: item.updatedAt,
            });
        }
    }

    // 4. Check for reused passwords across different domains
    const domainPasswordMap = new Map<string, Set<string>>();
    for (const item of passwordItems) {
        if (!item.websiteUrl || !item.password) continue;
        try {
            const domain = new URL(item.websiteUrl).hostname;
            const existing = domainPasswordMap.get(item.password) || new Set();
            existing.add(domain);
            domainPasswordMap.set(item.password, existing);
        } catch {
            // Invalid URL, skip
        }
    }
    for (const [, domains] of domainPasswordMap) {
        if (domains.size >= 2) {
            reusedCount += domains.size;
        }
    }

    // Calculate score (weighted)
    const totalPasswords = passwordItems.length;
    if (totalPasswords === 0) {
        return {
            score: 100,
            totalItems: items.length,
            passwordItems: 0,
            issues: [],
            stats: { weak: 0, duplicate: 0, old: 0, reused: 0, strong: 0 },
        };
    }

    const weakPenalty = (weakCount / totalPasswords) * 40;
    const dupPenalty = (duplicateCount / totalPasswords) * 30;
    const oldPenalty = (oldCount / totalPasswords) * 15;
    const reusedPenalty = Math.min((reusedCount / totalPasswords) * 15, 15);
    const score = Math.max(0, Math.round(100 - weakPenalty - dupPenalty - oldPenalty - reusedPenalty));

    const strongCount = totalPasswords - weakCount;

    return {
        score,
        totalItems: items.length,
        passwordItems: totalPasswords,
        issues,
        stats: {
            weak: weakCount,
            duplicate: duplicateCount,
            old: oldCount,
            reused: reusedCount,
            strong: strongCount > 0 ? strongCount : 0,
        },
    };
}
