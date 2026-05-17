// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Umlaut/UTF-8 encoding guardrails.
 *
 * This test exists because German Umlauts (ä/ö/ü/ß and uppercase variants)
 * in user-facing strings have broken multiple times in this repo:
 *
 *  1. UTF-8 files were reopened as Windows-1252 / Latin-1 by an editor and
 *     saved back, producing classical mojibake like `Ã¤`/`Ã¶`/`Ã¼`/`ÃŸ`.
 *  2. To work around that mojibake, German strings were rewritten with
 *     ASCII fallbacks ("ae" / "oe" / "ue" / "ss"), which is acceptable for
 *     search keywords but NOT for user-facing labels, error messages,
 *     dialog texts, patch notes or i18n locales.
 *
 * The fixes for both classes of bugs are:
 *  - `.editorconfig` and `.gitattributes` pin every text file to UTF-8 + LF.
 *  - This test catches regressions in source code, locales, CHANGELOG and
 *    release workflow notes.
 *
 * If this test fails, the right answer is to write proper Umlauts. Do NOT
 * rewrite German strings to ASCII fallbacks to silence the test.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { glob } from 'glob';

// vitest sets process.cwd() to the project root, which is exactly what we
// want here. Avoid `fileURLToPath(import.meta.url)` because vitest's source
// map may report a non-`file://` URL in some test environments.
const REPO_ROOT = resolve(process.cwd());

// Files we never scan: tests that intentionally contain mojibake/ASCII
// patterns as test inputs, generated artifacts, archive docs, and node_modules.
const IGNORE_GLOBS = [
    'node_modules/**',
    'dist/**',
    '.git/**',
    '.codex-logs/**',
    'docs/archive/**',
    'src/test/umlaut-encoding-contracts.test.ts',
    'temp_*.txt',
    '**/*.log',
    'CHANGELOG.md.bak',
] as const;

// Classical UTF-8-as-Latin-1 mojibake pairs. If any of these survive in
// production text, the file was edited with a non-UTF-8-aware tool.
const MOJIBAKE_PATTERNS: ReadonlyArray<RegExp> = [
    /Ã¤/, // ä
    /Ã¶/, // ö
    /Ã¼/, // ü
    /Ã„/, // Ä
    /Ã–/, // Ö
    /Ãœ/, // Ü
    /ÃŸ/, // ß
];

// ASCII-Umlaut-Ausweichungen that are ONLY allowed inside search keyword
// arrays (where having both 'geräte' and 'geraete' aids discoverability),
// but never inside user-facing strings, locale values, or patch notes.
//
// We restrict the patterns to clearly German words to avoid false positives
// in English content ("Manager", "Source", "feature", etc.).
const ASCII_FALLBACK_WORDS: ReadonlyArray<RegExp> = [
    /\b(?:Eintraege|Eintraegen)\b/,
    /\bloeschen\b/i,
    /\bgeloescht\b/i,
    /\b(?:Geraet|Geraete)\b/,
    /\bSchluessel\b/,
    /\bverfuegbar\b/,
    /\benthaelt\b/,
    /\bWaehle\b/,
    /\bdurchgaengig\b/,
    /\bueberarbeitet\b/,
    /\bkoennen\b/,
    /\bIdentitaet\b/,
    /\bEndgueltig\b/i,
    /\bQuarantaene\b/,
    /\bAenderung\b/,
    /\bvollstaendig\b/,
    /\bGeraetevertrauen\b/,
    /\bPasswoerter\b/,
    /\bPruefung\b/,
    /\bPruefen\b/,
    /\bPraefix\b/,
    /\bStaerke\b/,
    /\bzusaetzlich\b/i,
    /\bschwaecher\b/,
    /\bgroesser\b/i,
    /\bvertrauenswuerdig/i,
    /\bzuverlaessig\b/,
    /\bAenderungen\b/,
    /\bgeloeschte\b/,
    /\bGeraete-Recovery\b/,
];

// Files that intentionally contain ASCII fallback words (e.g., search
// keyword arrays where both variants are desirable). Lines that match these
// markers are exempted from the ASCII-fallback check.
const ASCII_FALLBACK_LINE_EXEMPTIONS: ReadonlyArray<RegExp> = [
    // coreSettingsSections.tsx: keywords arrays carry both variants on purpose
    // so the in-app search finds the entry whether or not the user types
    // Umlauts.
    /keywords:\s*\[/,
];

const TEXT_FILE_GLOBS = [
    'src/**/*.{ts,tsx}',
    'src/i18n/**/*.json',
    'index.html',
    'CHANGELOG.md',
    'README.md',
    '.github/workflows/*.yml',
] as const;

interface OffendingHit {
    file: string;
    line: number;
    snippet: string;
    pattern: string;
}

function scanFiles(patternsToFind: ReadonlyArray<RegExp>, allowLineExemptions: boolean): OffendingHit[] {
    const offenders: OffendingHit[] = [];
    for (const pattern of TEXT_FILE_GLOBS) {
        const matches = glob.sync(pattern, {
            cwd: REPO_ROOT,
            ignore: [...IGNORE_GLOBS],
            absolute: true,
            nodir: true,
        });
        for (const filePath of matches) {
            const content = readFileSync(filePath, 'utf8');
            const lines = content.split(/\r?\n/);
            for (let index = 0; index < lines.length; index += 1) {
                const line = lines[index];
                if (
                    allowLineExemptions
                    && ASCII_FALLBACK_LINE_EXEMPTIONS.some((exempt) => exempt.test(line))
                ) {
                    continue;
                }
                for (const regex of patternsToFind) {
                    if (regex.test(line)) {
                        offenders.push({
                            file: filePath.replace(`${REPO_ROOT}\\`, '').replace(`${REPO_ROOT}/`, ''),
                            line: index + 1,
                            snippet: line.trim().slice(0, 200),
                            pattern: regex.source,
                        });
                    }
                }
            }
        }
    }
    return offenders;
}

describe('Umlaut / UTF-8 encoding contracts', () => {
    it('contains no Latin-1 → UTF-8 mojibake (Ã¤ / Ã¶ / Ã¼ / ÃŸ …) in source, locales or patch notes', () => {
        const offenders = scanFiles(MOJIBAKE_PATTERNS, false);
        expect(
            offenders,
            offenders.length > 0
                ? `Mojibake sequences detected. Fix the encoding (UTF-8) instead of rewriting Umlauts as ASCII:\n${
                    offenders.map((o) => `  ${o.file}:${o.line}  [${o.pattern}]  ${o.snippet}`).join('\n')
                }`
                : '',
        ).toEqual([]);
    });

    it('uses real Umlauts (ä/ö/ü/ß) in user-facing German text instead of ASCII fallbacks', () => {
        const offenders = scanFiles(ASCII_FALLBACK_WORDS, true);
        expect(
            offenders,
            offenders.length > 0
                ? `ASCII Umlaut fallbacks detected in user-facing text. Use real Umlauts (ä/ö/ü/ß) — do not regress German texts to "ae"/"oe"/"ue"/"ss":\n${
                    offenders.map((o) => `  ${o.file}:${o.line}  [${o.pattern}]  ${o.snippet}`).join('\n')
                }`
                : '',
        ).toEqual([]);
    });
});
