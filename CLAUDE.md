# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Note:** `AGENTS.md` contains the full authoritative policy (coding style, commit rules, security directives). This file summarises the essentials and adds architecture context.

---

## Commands

```bash
npm run dev            # Vite dev server on http://localhost:8080
npm run build          # Production build to dist/
npm run lint           # ESLint (ts/tsx files)
npm run test           # Vitest — run all tests once (CI mode)
npm run test:watch     # Vitest — watch mode

# Run a single test file
npx vitest run src/test/encryption-roundtrip.test.ts

# Run tests matching a name pattern
npx vitest run -t "should preserve data"

# Run all tests in a directory
npx vitest run src/services/
```

Copy `env.example` → `.env` and set `VITE_SUPABASE_PROJECT_ID`, `VITE_SUPABASE_PUBLISHABLE_KEY`, `VITE_SUPABASE_URL`, `VITE_SITE_URL`.

---

## Architecture

### Zero-Knowledge Security Model

All encryption and decryption happens **client-side only**. The server never sees plaintext.

- `src/services/cryptoService.ts` — AES-256-GCM encryption, Argon2id key derivation (KDF v1/v2 with auto-migration on unlock), versioned `KDF_PARAMS`
- `src/services/keyMaterialService.ts` — in-memory key lifecycle management
- `src/services/secureBuffer.ts` — zeroing of sensitive byte arrays after use
- `src/services/pqCryptoService.ts` — post-quantum layer using `@noble/post-quantum`
- `src/services/opaqueService.ts` — OPAQUE protocol (password-authenticated key exchange) via `@serenity-kit/opaque`

### Open-Core / Extension Registry

Core is always available; premium features are injected at runtime by `@singra/premium`.

- `src/extensions/registry.ts` — maps named **slots** → React components, routes, and service hooks
- `src/extensions/initPremium.ts` — called at startup; registers premium components/routes if the package is present
- Core consumes slots via `getExtension('slot.name')` — returns `null` if premium is absent (no crash)
- New premium-only UI/routes must be registered via `registerExtension` / `registerRoute` in `initPremium.ts`

### Context Provider Hierarchy (App.tsx)

```
QueryClientProvider
  ThemeProvider
    AuthProvider          ← Supabase auth session, OPAQUE unlock
      SubscriptionProvider  ← plan tier, feature gates
        VaultProvider       ← decrypted vault items, CRUD ops
```

### Supabase Back-End

- Project ID: `lcrtadxlojaucwapgzmy`
- SQL migrations: `supabase/migrations/`
- Edge Functions (Deno): `supabase/functions/` — covers OPAQUE auth (`auth-opaque`, `auth-register`, `auth-session`, `auth-reset-password`, `auth-recovery`), rate limiting, WebAuthn
- Generated TypeScript types: `src/integrations/supabase/types.ts` — regenerate after schema changes

### Routing

Core routes are statically declared in `App.tsx`. Premium routes are dynamically injected via `getExtensionRoutes()`. All protected routes are wrapped in `<ProtectedRoute>`.

---

## Key Conventions (see AGENTS.md for full detail)

- **i18n**: Every user-facing string uses `t('key')` from `react-i18next`. Locale files: `src/i18n/locales/de.json` and `en.json`. German is the fallback. New features need entries in both files.
- **shadcn/ui**: Files in `src/components/ui/` are generated — do not hand-edit them.
- **Services**: Named `export function` (never default, never arrow). Errors propagate from Web Crypto APIs; use `{ error: Error | null }` for fallible ops.
- **Components**: Named `export function ComponentName()`. Only pages use `export default`.
- **Indentation**: 4 spaces in hand-written code; 2 spaces in shadcn/ui files and tests.
- **Imports**: Use `@/` alias for everything under `src/`. Relative paths only for sibling files.
- TypeScript is configured with `strict: false` / `noImplicitAny: false`.
- WASM is enabled (`vite-plugin-wasm` + `vite-plugin-top-level-await`) for `argon2id`.

---

## Testing

- Framework: **Vitest** + Testing Library + jsdom
- Global setup (`src/test/setup.ts`) mocks Web Crypto API, IndexedDB, Clipboard, and console
- Property-based tests use `fast-check` (see `encryption-roundtrip.test.ts`)
- Test files: `*.test.ts` / `*.spec.ts` under `src/`

---

## Git & Branch Rules

- Work on a `feature/<topic>` branch — never commit directly to `main`.
- Run `npm run lint` and `npm run test` before pushing.
- PRs must note env/migration changes and include screenshots for UI changes.
