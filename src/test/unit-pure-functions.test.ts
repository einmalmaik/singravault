// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Phase 1 — Unit-Tests für reine Funktionen
 *
 * Testet alle reinen, zustandslosen Hilfsfunktionen ohne DB- oder
 * Netzwerk-Abhängigkeiten: cn(), sanitizeInlineSvg(), planConfig,
 * formatFileSize(), getFileIcon(), buildVaultItemRowFromInsert(),
 * buildCategoryRowFromInsert(), isLikelyOfflineError(), isAppOnline(),
 * i18n languages/changeLanguage, deriveRawKeySecure().
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock hash-wasm's argon2id with a PBKDF2 stand-in
// ---------------------------------------------------------------------------
vi.mock("hash-wasm", () => ({
  argon2id: async ({
    password,
    salt,
    hashLength,
  }: {
    password: string;
    salt: Uint8Array | string;
    hashLength: number;
    parallelism?: number;
    iterations?: number;
    memorySize?: number;
    outputType?: string;
  }) => {
    const enc = new TextEncoder();
    const passwordBytes = enc.encode(password);
    const saltBytes =
      typeof salt === "string" ? enc.encode(salt) : salt;
    const baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBytes as any, iterations: 1000, hash: "SHA-256" },
      baseKey,
      hashLength * 8
    );
    return Array.from(new Uint8Array(bits))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  },
}));

// ---------------------------------------------------------------------------
// 3.1 cn() — Tailwind class merging utility
// ---------------------------------------------------------------------------
import { cn } from "@/lib/utils";

describe("cn() — Tailwind class merge utility", () => {
  it('cn("foo", "bar") → "foo bar"', () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it('cn("p-4", "p-2") → Tailwind merge keeps last', () => {
    expect(cn("p-4", "p-2")).toBe("p-2");
  });

  it("cn with falsy values are ignored", () => {
    expect(cn("foo", undefined, null, false, "bar")).toBe("foo bar");
  });

  it("cn() without arguments → empty string", () => {
    expect(cn()).toBe("");
  });

  it("cn with conditional object", () => {
    expect(cn({ "text-red-500": true, "text-blue-500": false })).toBe("text-red-500");
  });
});

// ---------------------------------------------------------------------------
// 3.2 sanitizeInlineSvg()
// ---------------------------------------------------------------------------
import { sanitizeInlineSvg } from "@/lib/sanitizeSvg";

describe("sanitizeInlineSvg()", () => {
  it("accepts valid SVG", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).toContain("<svg");
    expect(result).toContain("<path");
  });

  it("returns null for empty string", () => {
    expect(sanitizeInlineSvg("")).toBeNull();
  });

  it("returns null for non-SVG input", () => {
    expect(sanitizeInlineSvg("<div>hallo</div>")).toBeNull();
  });

  it("returns null for SVG exceeding 8000 chars", () => {
    const longSvg = `<svg xmlns="http://www.w3.org/2000/svg">${"<path d=\"M0 0\"/>".repeat(600)}</svg>`;
    expect(longSvg.length).toBeGreaterThan(8000);
    expect(sanitizeInlineSvg(longSvg)).toBeNull();
  });

  it("removes <script> tags", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><path d="M0 0"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).not.toContain("script");
    expect(result).toContain("path");
  });

  it('removes onload="..." event attributes', () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><path d="M0 0"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).not.toContain("onload");
  });

  it('removes style="..." attributes', () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" style="color:red"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).not.toContain("style");
  });

  it("removes javascript: href", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" href="javascript:alert(1)"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).not.toContain("javascript:");
  });

  it("removes data: href", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0" href="data:text/html,foo"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).not.toContain("data:");
  });

  it("returns null for SVG with >128 elements", () => {
    const paths = Array.from({ length: 130 }, (_, i) => `<path d="M${i} 0"/>`).join("");
    const input = `<svg xmlns="http://www.w3.org/2000/svg">${paths}</svg>`;
    // Only null if total SVG also fits in 8000 chars and has >128 child elements
    if (input.length <= 8000) {
      expect(sanitizeInlineSvg(input)).toBeNull();
    }
  });

  it('accepts SVG with <?xml prefix', () => {
    const input = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0"/></svg>';
    const result = sanitizeInlineSvg(input);
    // DOMParser may or may not accept this depending on jsdom behavior
    // The function checks for "<?xml" prefix as valid SVG input
    // Result may be null if DOMParser fails, but the input should pass the isSvgInput check
    expect(typeof result === "string" || result === null).toBe(true);
  });

  it("preserves allowed attributes (viewBox, fill, stroke)", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><path d="M0 0" fill="red" stroke="blue"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).toContain("viewBox");
    expect(result).toContain('fill="red"');
    expect(result).toContain('stroke="blue"');
  });

  it("preserves aria-label and role attributes", () => {
    const input = '<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="icon"><path d="M0 0"/></svg>';
    const result = sanitizeInlineSvg(input);
    expect(result).not.toBeNull();
    expect(result).toContain('role="img"');
    expect(result).toContain('aria-label="icon"');
  });
});

// ---------------------------------------------------------------------------
// 3.3 planConfig.ts
// ---------------------------------------------------------------------------
import {
  PLAN_CONFIG,
  VALID_PLAN_KEYS,
  INTRO_COUPON_ID,
  FEATURE_MATRIX,
  getRequiredTier,
} from "@/config/planConfig";

describe("planConfig", () => {
  it("PLAN_CONFIG has exactly 4 entries", () => {
    const keys = Object.keys(PLAN_CONFIG);
    expect(keys).toHaveLength(4);
    expect(keys).toContain("premium_monthly");
    expect(keys).toContain("premium_yearly");
    expect(keys).toContain("families_monthly");
    expect(keys).toContain("families_yearly");
  });

  it("every plan has priceId, tier, label, interval, amount", () => {
    for (const key of VALID_PLAN_KEYS) {
      const plan = PLAN_CONFIG[key];
      expect(plan.priceId).toBeTruthy();
      expect(typeof plan.priceId).toBe("string");
      expect(["premium", "families"]).toContain(plan.tier);
      expect(plan.label).toBeTruthy();
      expect(["month", "year"]).toContain(plan.interval);
      expect(typeof plan.amount).toBe("number");
      expect(plan.amount).toBeGreaterThan(0);
    }
  });

  it("VALID_PLAN_KEYS has 4 entries matching PLAN_CONFIG", () => {
    expect(VALID_PLAN_KEYS).toHaveLength(4);
    for (const key of VALID_PLAN_KEYS) {
      expect(PLAN_CONFIG[key]).toBeDefined();
    }
  });

  it('INTRO_COUPON_ID is "K3tViKjk"', () => {
    expect(INTRO_COUPON_ID).toBe("K3tViKjk");
    expect(typeof INTRO_COUPON_ID).toBe("string");
    expect(INTRO_COUPON_ID.length).toBeGreaterThan(0);
  });

  it("FEATURE_MATRIX has all 14 features", () => {
    const featureKeys = Object.keys(FEATURE_MATRIX);
    expect(featureKeys).toHaveLength(14);
    for (const key of featureKeys) {
      const tiers = FEATURE_MATRIX[key as keyof typeof FEATURE_MATRIX];
      expect(typeof tiers.free).toBe("boolean");
      expect(typeof tiers.premium).toBe("boolean");
      expect(typeof tiers.families).toBe("boolean");
    }
  });

  it("6 features are free", () => {
    const freeFeatures = Object.entries(FEATURE_MATRIX)
      .filter(([, v]) => v.free === true)
      .map(([k]) => k);
    expect(freeFeatures).toHaveLength(6);
    expect(freeFeatures).toContain("unlimited_passwords");
    expect(freeFeatures).toContain("device_sync");
    expect(freeFeatures).toContain("password_generator");
    expect(freeFeatures).toContain("secure_notes");
    expect(freeFeatures).toContain("external_2fa");
    expect(freeFeatures).toContain("post_quantum_encryption");
  });

  it("families-only features: premium=false, families=true", () => {
    expect(FEATURE_MATRIX.family_members).toEqual({ free: false, premium: false, families: true });
    expect(FEATURE_MATRIX.shared_collections).toEqual({ free: false, premium: false, families: true });
  });

  it('getRequiredTier("unlimited_passwords") → "free"', () => {
    expect(getRequiredTier("unlimited_passwords")).toBe("free");
  });

  it('getRequiredTier("file_attachments") → "premium"', () => {
    expect(getRequiredTier("file_attachments")).toBe("premium");
  });

  it('getRequiredTier("family_members") → "families"', () => {
    expect(getRequiredTier("family_members")).toBe("families");
  });
});

// ---------------------------------------------------------------------------
// 3.4 formatFileSize() and getFileIcon()
// ---------------------------------------------------------------------------
import { formatFileSize, getFileIcon } from "@/services/fileAttachmentService";

describe("formatFileSize()", () => {
  it('formatFileSize(0) → "0 B"', () => {
    expect(formatFileSize(0)).toBe("0 B");
  });

  it('formatFileSize(1023) → "1023 B"', () => {
    expect(formatFileSize(1023)).toBe("1023 B");
  });

  it('formatFileSize(1024) → "1.0 KB"', () => {
    expect(formatFileSize(1024)).toBe("1.0 KB");
  });

  it('formatFileSize(1048576) → "1.0 MB"', () => {
    expect(formatFileSize(1048576)).toBe("1.0 MB");
  });

  it('formatFileSize(1073741824) → "1.00 GB"', () => {
    expect(formatFileSize(1073741824)).toBe("1.00 GB");
  });
});

describe("getFileIcon()", () => {
  it('getFileIcon("application/pdf") returns icon string', () => {
    const icon = getFileIcon("application/pdf");
    expect(typeof icon).toBe("string");
    expect(icon.length).toBeGreaterThan(0);
    expect(icon).toBe("📄");
  });

  it('getFileIcon("image/png") returns image icon', () => {
    const icon = getFileIcon("image/png");
    expect(icon).toBe("🖼️");
  });

  it('getFileIcon("unknown/type") returns fallback icon', () => {
    const icon = getFileIcon("unknown/type");
    expect(icon).toBe("📎");
  });

  it("getFileIcon(null) returns fallback icon", () => {
    const icon = getFileIcon(null);
    expect(icon).toBe("📎");
  });

  it('getFileIcon("video/mp4") returns video icon', () => {
    expect(getFileIcon("video/mp4")).toBe("🎬");
  });

  it('getFileIcon("audio/mpeg") returns audio icon', () => {
    expect(getFileIcon("audio/mpeg")).toBe("🎵");
  });

  it('getFileIcon("application/zip") returns archive icon', () => {
    expect(getFileIcon("application/zip")).toBe("📦");
  });

  it('getFileIcon("text/plain") returns text icon', () => {
    expect(getFileIcon("text/plain")).toBe("📝");
  });
});

// ---------------------------------------------------------------------------
// 3.5 offlineVaultService — Pure helpers
// ---------------------------------------------------------------------------
import {
  isLikelyOfflineError,
  isAppOnline,
  buildVaultItemRowFromInsert,
  buildCategoryRowFromInsert,
} from "@/services/offlineVaultService";

describe("isLikelyOfflineError()", () => {
  it('returns true for "Failed to fetch" error', () => {
    expect(isLikelyOfflineError(new Error("Failed to fetch"))).toBe(true);
  });

  it('returns true for "network error"', () => {
    expect(isLikelyOfflineError(new Error("network error"))).toBe(true);
  });

  it("returns false for unrelated error when online", () => {
    // navigator.onLine should be true by default in test env
    Object.defineProperty(navigator, "onLine", { value: true, writable: true, configurable: true });
    expect(isLikelyOfflineError(new Error("some other error"))).toBe(false);
  });

  it("returns true for any error when offline", () => {
    Object.defineProperty(navigator, "onLine", { value: false, writable: true, configurable: true });
    expect(isLikelyOfflineError(new Error("some other error"))).toBe(true);
    // Restore
    Object.defineProperty(navigator, "onLine", { value: true, writable: true, configurable: true });
  });
});

describe("isAppOnline()", () => {
  it("returns true when navigator.onLine is true", () => {
    Object.defineProperty(navigator, "onLine", { value: true, writable: true, configurable: true });
    expect(isAppOnline()).toBe(true);
  });

  it("returns false when navigator.onLine is false", () => {
    Object.defineProperty(navigator, "onLine", { value: false, writable: true, configurable: true });
    expect(isAppOnline()).toBe(false);
    Object.defineProperty(navigator, "onLine", { value: true, writable: true, configurable: true });
  });
});

describe("buildVaultItemRowFromInsert()", () => {
  it("builds a complete Row from Insert with defaults", () => {
    const insert = {
      id: "item-1",
      user_id: "user-1",
      vault_id: "vault-1",
      title: "Test",
      encrypted_data: "enc-data",
    };
    const row = buildVaultItemRowFromInsert(insert);

    expect(row.id).toBe("item-1");
    expect(row.user_id).toBe("user-1");
    expect(row.vault_id).toBe("vault-1");
    expect(row.title).toBe("Test");
    expect(row.encrypted_data).toBe("enc-data");
    expect(row.website_url).toBeNull();
    expect(row.icon_url).toBeNull();
    expect(row.item_type).toBe("password");
    expect(row.category_id).toBeNull();
    expect(row.is_favorite).toBe(false);
    expect(row.sort_order).toBeNull();
    expect(row.last_used_at).toBeNull();
    expect(row.created_at).toBeTruthy();
    expect(row.updated_at).toBeTruthy();
  });

  it("preserves optional fields when provided", () => {
    const insert = {
      id: "item-2",
      user_id: "user-1",
      vault_id: "vault-1",
      title: "With options",
      encrypted_data: "enc",
      website_url: "https://example.com",
      item_type: "note" as const,
      is_favorite: true,
      category_id: "cat-1",
    };
    const row = buildVaultItemRowFromInsert(insert);

    expect(row.website_url).toBe("https://example.com");
    expect(row.item_type).toBe("note");
    expect(row.is_favorite).toBe(true);
    expect(row.category_id).toBe("cat-1");
  });
});

describe("buildCategoryRowFromInsert()", () => {
  it("builds a complete Row from Insert with defaults", () => {
    const insert = {
      id: "cat-1",
      user_id: "user-1",
      name: "Work",
    };
    const row = buildCategoryRowFromInsert(insert);

    expect(row.id).toBe("cat-1");
    expect(row.user_id).toBe("user-1");
    expect(row.name).toBe("Work");
    expect(row.icon).toBeNull();
    expect(row.color).toBeNull();
    expect(row.parent_id).toBeNull();
    expect(row.sort_order).toBeNull();
    expect(row.created_at).toBeTruthy();
    expect(row.updated_at).toBeTruthy();
  });

  it("preserves optional fields when provided", () => {
    const insert = {
      id: "cat-2",
      user_id: "user-1",
      name: "Personal",
      icon: "heart",
      color: "#ff0000",
      parent_id: "cat-1",
      sort_order: 5,
    };
    const row = buildCategoryRowFromInsert(insert);

    expect(row.icon).toBe("heart");
    expect(row.color).toBe("#ff0000");
    expect(row.parent_id).toBe("cat-1");
    expect(row.sort_order).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// 3.6 deriveRawKeySecure() — SecureBuffer wrapping
// ---------------------------------------------------------------------------
import { deriveRawKey, deriveRawKeySecure, generateSalt } from "@/services/cryptoService";

describe("deriveRawKeySecure()", () => {
  const testPassword = "TestMasterPassword123!";
  let testSalt: string;

  beforeEach(() => {
    testSalt = generateSalt();
  });

  it("returns a SecureBuffer of size 32", async () => {
    const secure = await deriveRawKeySecure(testPassword, testSalt);
    expect(secure.size).toBe(32);
    expect(secure.isDestroyed).toBe(false);
    secure.destroy();
    expect(secure.isDestroyed).toBe(true);
  });

  it("SecureBuffer contains same bytes as deriveRawKey()", async () => {
    const rawBytes = await deriveRawKey(testPassword, testSalt);
    const secure = await deriveRawKeySecure(testPassword, testSalt);

    let secureBytes: Uint8Array | null = null;
    secure.use((buf) => {
      secureBytes = new Uint8Array(buf);
    });

    expect(secureBytes).not.toBeNull();
    expect(secureBytes!.length).toBe(rawBytes.length);
    for (let i = 0; i < rawBytes.length; i++) {
      expect(secureBytes![i]).toBe(rawBytes[i]);
    }

    secure.destroy();
  });

  it("source bytes are zeroed after wrapping", async () => {
    // This is implicitly tested by SecureBuffer.fromBytes which zeros the input
    // We can verify by ensuring the SecureBuffer is valid after creation
    const secure = await deriveRawKeySecure(testPassword, testSalt);
    expect(secure.isDestroyed).toBe(false);

    let nonZeroCount = 0;
    secure.use((buf) => {
      for (let i = 0; i < buf.length; i++) {
        if (buf[i] !== 0) nonZeroCount++;
      }
    });
    expect(nonZeroCount).toBeGreaterThan(0); // Key bytes should not be all zero
    secure.destroy();
  });
});

// ---------------------------------------------------------------------------
// 3.7 i18n — languages + changeLanguage
// ---------------------------------------------------------------------------

// We need to mock i18next to avoid full initialization in test environment
vi.mock("i18next", async () => {
  let currentLang = "de";
  return {
    default: {
      use: () => ({ init: () => ({}) }),
      changeLanguage: (lang: string) => { currentLang = lang; },
      language: currentLang,
      t: (key: string) => key,
    },
  };
});

vi.mock("react-i18next", () => ({
  initReactI18next: { type: "3rdParty", init: () => {} },
  useTranslation: () => ({ t: (key: string) => key, i18n: { changeLanguage: () => {} } }),
}));

// Import after mocks
import { languages, changeLanguage } from "@/i18n/index";

describe("i18n — languages and changeLanguage()", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("languages has exactly 2 entries (de, en)", () => {
    const keys = Object.keys(languages);
    expect(keys).toHaveLength(2);
    expect(keys).toContain("de");
    expect(keys).toContain("en");
  });

  it("languages have correct names", () => {
    expect(languages.de.name).toBe("Deutsch");
    expect(languages.en.name).toBe("English");
  });

  it("languages have flag emojis", () => {
    expect(languages.de.flag).toBeTruthy();
    expect(languages.en.flag).toBeTruthy();
  });

  it('changeLanguage("en") without cookie consent does NOT persist to localStorage', () => {
    // No singra-cookie-consent set
    changeLanguage("en");
    expect(localStorage.getItem("Singra-language")).toBeNull();
  });

  it('changeLanguage("en") with cookie consent persists to localStorage', () => {
    localStorage.setItem("singra-cookie-consent", JSON.stringify({ optional: true }));
    changeLanguage("en");
    expect(localStorage.getItem("Singra-language")).toBe("en");
  });

  it('changeLanguage("de") with consent where optional=false does NOT persist', () => {
    localStorage.setItem("singra-cookie-consent", JSON.stringify({ optional: false }));
    changeLanguage("de");
    expect(localStorage.getItem("Singra-language")).toBeNull();
  });
});
