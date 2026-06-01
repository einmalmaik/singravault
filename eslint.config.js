import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "src-tauri/target/**"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-unused-vars": "off",
    },
  },

  // ── DIS crypto-centralization guardrail ──────────────────────────────────
  // Vault item encryption (Argon2id KDF, AES-256-GCM) and post-quantum hybrid
  // key wrapping (ML-KEM-768 + RSA-4096) now live exclusively in the audited
  // @dis/shield package — "Powered by DIS — Defensive Integration Shield".
  // Application code consumes them ONLY through the cryptoService /
  // pqCryptoService adapters, never by importing crypto libraries directly.
  // This rule fails closed so new code cannot reintroduce in-tree crypto.
  {
    files: ["src/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "hash-wasm",
              message:
                "Do not import hash-wasm directly. Argon2id key derivation lives in @dis/shield; consume it via services/cryptoService.",
            },
            {
              name: "@noble/post-quantum",
              message:
                "Do not import @noble/post-quantum directly. ML-KEM hybrid wrapping lives in @dis/shield; consume it via services/pqCryptoService.",
            },
          ],
          patterns: [
            {
              group: ["@noble/post-quantum/*"],
              message:
                "Do not import @noble/post-quantum directly. ML-KEM hybrid wrapping lives in @dis/shield; consume it via services/pqCryptoService.",
            },
          ],
        },
      ],
    },
  },
  // Allowlist: the DIS adapters own the centralized crypto surface, and a few
  // legacy crypto modules + their tests still call Argon2id (hash-wasm) directly
  // and are tracked as the next cutover targets (deviceKey / TOTP). They remain
  // forbidden from importing @noble/post-quantum.
  {
    files: [
      "src/services/cryptoService.ts",
      "src/services/pqCryptoService.ts",
      "src/services/deviceKeyService.ts",
      "src/services/twoFactorService.ts",
      "**/*.test.{ts,tsx}",
      "src/test/**/*.{ts,tsx}",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@noble/post-quantum",
              message:
                "Do not import @noble/post-quantum directly. ML-KEM hybrid wrapping lives in @dis/shield; consume it via services/pqCryptoService.",
            },
          ],
          patterns: [
            {
              group: ["@noble/post-quantum/*"],
              message:
                "Do not import @noble/post-quantum directly. ML-KEM hybrid wrapping lives in @dis/shield; consume it via services/pqCryptoService.",
            },
          ],
        },
      ],
    },
  },
);
