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
  // Since the Phase-6 full extraction, EVERY cryptographic primitive — Argon2id
  // KDF, AES-256-GCM, HKDF, HMAC, SHA-256/SHA-1, ECDSA P-256 signing, TOTP,
  // ML-KEM-768 hybrid wrapping, CSPRNG randomness and UUIDs — lives exclusively
  // in the audited @dis/shield package ("Powered by DIS — Defensive Integration
  // Shield"). Application code consumes them ONLY through @dis/shield (or the
  // cryptoService / pqCryptoService re-export adapters), never by importing
  // crypto libraries or calling WebCrypto directly. These rules fail closed so
  // new code cannot reintroduce in-tree crypto. Tests are exempt: they may use
  // raw primitives to build fixtures and cross-check DIS behaviour.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["**/*.test.{ts,tsx}", "src/test/**/*.{ts,tsx}", "src/test-stubs/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "hash-wasm",
              message:
                "Do not import hash-wasm directly. Argon2id lives in @dis/shield/kdf.",
            },
            {
              name: "otpauth",
              message:
                "Do not import otpauth directly. TOTP lives in @dis/shield/totp.",
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
      "no-restricted-properties": [
        "error",
        {
          object: "crypto",
          property: "subtle",
          message:
            "Do not call WebCrypto directly. Every primitive lives in @dis/shield (aead/kdf/integrity/signing). Capability checks may use `'subtle' in crypto`.",
        },
        {
          object: "crypto",
          property: "getRandomValues",
          message:
            "Do not call crypto.getRandomValues directly. Use randomBytes/fillRandom/randomInt from @dis/shield/random.",
        },
        {
          object: "crypto",
          property: "randomUUID",
          message:
            "Do not call crypto.randomUUID directly. Use randomUuid from @dis/shield/random.",
        },
      ],
    },
  },
);
