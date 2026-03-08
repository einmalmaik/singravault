# Repository Guidelines

Singra PW — a zero-knowledge password manager built with React, TypeScript, Vite, and Supabase.

## (VERPFLICHTEND)

Du bist ein autonomer Coding-Agent, der im SINGRA-Repository arbeitet (React 18 + TypeScript + Vite + Tailwind + shadcn/ui; Supabase Postgres/Auth/Storage/Edge Functions mit Deno). Folge diesem Dokument als verbindlicher Policy.

## Primäre Direktiven (Nicht verhandelbar)
- Bewahre die bestehende Architektur und Konventionen. Führe keine neuen Frameworks, Patterns oder Dependencies ein, außer es ist ausdrücklich gewünscht und begründet.
- Bevorzuge Korrektheit und Sicherheit vor Geschwindigkeit. Mache niemals „Quick-Fixes“, indem du Guardrails, Validierungen, RLS, Permission-Checks oder Sicherheitssysteme abschwächst.
- Wenn Anforderungen unklar oder riskant sind, stelle VOR der Implementierung Rückfragen. Wenn es zeitkritisch ist und die Unklarheit gering: wähle die sicherste Minimaländerung und dokumentiere Annahmen.

## Multi-Repo Boundary (Verpflichtend)
- In diesem Projekt existieren zwei getrennte Repositories:
  - `F:\Projekte Main\singravault` = **Core** (Open-Source-Basis)
  - `F:\Projekte Main\singra-premium` = **Premium** (nicht Open Source, privat)
- Arbeite bei Anfragen immer repo-bewusst. Prüfe zuerst, ob die Änderung in den Core oder in Premium gehört.
- **Core enthält nur Kernfunktionen und Extension-Verträge.** Premium-/Bezahl-/Internal-Team-Funktionen dürfen nicht als dauerhafte Business-Logik in den Core verschoben werden.
- Alles rund um `admin`, `support`, `subscription`, `billing`, `family`, `shared collections`, `emergency access`, Premium-Seiten, Premium-Services und interne Teamrechte gehört grundsätzlich ins **Premium-Repo**, außer der Nutzer verlangt ausdrücklich eine Änderung an der Core-Schnittstelle.
- Änderungen im Core für Premium-Themen dürfen nur die öffentliche Boundary betreffen:
  - Extension-Slots/Types
  - Registry-Verträge
  - stabile Interfaces, die Premium konsumiert
- Greife **nicht** aus dem Core auf interne Premium-Dateien oder `node_modules/@singra/premium/src/*` zu, außer der Nutzer verlangt explizit einen temporären Hotfix und die Abweichung wird klar dokumentiert.
- Wenn ein Fix beide Repos betrifft, arbeite in beiden Repos getrennt und halte die Verantwortlichkeiten sauber auseinander.

## Tooling & Verifikation (Anti-Halluzination)
- Wenn du es nicht weißt: VERIFIZIERE (Repo-Suche, Supabase MCP, Websuche), bevor du handelst.
- Erfinde niemals Tabellennamen, Spalten, Endpoints, Settings-Keys oder bestehende Funktionen. Finde sie zuerst (oder lege sie via Migration/Settings inkl. Dokumentation korrekt an).
- Wenn eine Aussage von externen Fakten abhängt (APIs, Libraries, CVEs, Preise, Limits): nutze Websuche und füge die Quellenlinks in PR/Zusammenfassung hinzu.

## Autonomer Arbeitsablauf (Immer)
1) Verstehe die Anfrage: Ziel + Akzeptanzkriterien + Constraints in eigenen Worten wiedergeben.
2) Architektur-Scan (verpflichtend): betroffene Layer identifizieren (UI, Hooks, Lib, Edge Functions, DB, RLS, Settings, Permissions).
3) Call-Site-Analyse (verpflichtend):
   - Wenn du Funktion/Modul A änderst, finde, wo es aufgerufen/genutzt wird.
   - Prüfe Downstream-Effekte, Contracts, Types und Error-Handling.
4) Plan: minimale Schritte, kleinster sicherer Diff. Identifiziere nötige Settings/Flags (im Admin Panel konfigurierbar).
5) Implementieren: kleine Commits, ein Thema pro Commit.
6) Tests + Verifikation (verpflichtend): relevante Commands ausführen, Tests hinzufügen, wenn Logik geändert wird.
7) Selbstkritik (verpflichtend): Edge-Cases, Security/Privacy-Risiken, Rollback-Plan und was du verifiziert hast auflisten.
8) Ausliefern: klare Change-Zusammenfassung + worauf man achten soll + wie man testet.

## Git- & Delivery-Regeln
- Arbeite NUR auf dem aktuellen Feature-Branch (oder erstelle einen, wenn keiner existiert, z.B. `feature/<topic>`).
- Pushe NIEMALS direkt auf `main`, `master` oder irgendeinen persönlichen/Default-Branch.
- Nach jedem abgeschlossenen Änderungspaket: erstelle einen Commit mit klarer Message (keine lang laufenden uncommitteten Arbeiten).
- Halte Commits fokussiert: ein Thema pro Commit, keine Vermischung unzusammenhängender Änderungen.
- Vor finaler Übergabe: stelle sicher, dass das Repo clean ist, keine Debug-Logs enthalten sind und Tests/Lint/Scan grün sind.


## Key Principles

- **i18n**: All user-facing strings must go through `useTranslation()` / `t('key')`. Translation files live in `src/i18n/locales/` (de.json, en.json). German is the default/fallback. New features must include translations for both languages.
- **Security-first**: This is a password manager. Treat all crypto, auth, and key-handling changes as high risk. Question your own changes. Add tests for any security-sensitive code.
- **Document changes**: Record significant changes in markdown files under `docs/`.

## Project Structure

```
src/
  pages/           Route-level screens (Landing, VaultPage, Auth, Settings, etc.)
  components/
    ui/            shadcn/ui primitives (do not hand-edit these)
    vault/         Vault domain components
    landing/       Landing page sections
    settings/      Settings domain components
    auth/          Auth-related components
    Subscription/  Subscription/payment components
  contexts/        React context providers (Auth, Vault, Theme, Subscription)
  hooks/           Custom React hooks
  services/        Crypto, security, business logic (pure functions, no React)
  i18n/            i18next setup + locale JSON files
  integrations/    Supabase client and generated types
  lib/             Small utilities (cn(), sanitizeSvg)
  config/          App configuration (plan tiers, feature matrix)
  test/            Vitest setup, test helpers, and test files
  email-templates/ HTML email templates for Supabase auth
public/            Static assets, PWA manifest, service worker
supabase/          Config, SQL migrations, Edge Functions
docs/              Project documentation (40+ files)
```

## Build, Lint, and Test Commands

```bash
npm i                  # Install dependencies
npm run dev            # Vite dev server on port 8080
npm run build          # Production build to dist/
npm run build:dev      # Development-mode build
npm run lint           # ESLint (ts/tsx files)
npm run test           # Vitest — run all tests once (CI mode)
npm run test:watch     # Vitest — watch mode
```

### Running a single test file

```bash
npx vitest run src/test/encryption-roundtrip.test.ts
npx vitest run src/services/rateLimiterService.test.ts
```

### Running tests matching a pattern

```bash
npx vitest run -t "should preserve data"
npx vitest run src/services/  # all tests under a directory
```

Test files must be named `*.test.ts` or `*.spec.ts` and placed under `src/` (typically co-located with the module or in `src/test/`). Setup file: `src/test/setup.ts`.

## Coding Style

### Formatting

- **Indentation**: Match the file you are editing. Hand-written code (services, contexts, components, pages) uses 4 spaces. shadcn/ui boilerplate and test files use 2 spaces.
- **Semicolons**: Always.
- **Quotes**: Single quotes in hand-written application code. Double quotes in shadcn/ui files, test files, and `App.tsx`.
- **Trailing commas**: Used in multi-line arrays/objects.

### Imports — Ordering

Group imports in this order, separated by blank lines:

1. React (`import { useState, useEffect } from 'react'`)
2. External libraries (`react-i18next`, `lucide-react`, `react-router-dom`, etc.)
3. Internal UI components (`@/components/ui/*`)
4. Internal contexts, hooks, services (`@/contexts/*`, `@/hooks/*`, `@/services/*`)
5. Relative/sibling imports (`./TOTPDisplay`, `./AuthContext`)
6. Side-effect imports (`import '@/i18n'`)

Always use the `@/*` path alias for imports from `src/`. Use relative paths (`./`) only for sibling files in the same directory.

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Component/page files | `PascalCase.tsx` | `VaultItemCard.tsx` |
| Hook files | `camelCase` or `kebab-case` | `useFeatureGate.ts`, `use-toast.ts` |
| Service files | `camelCase.ts` | `cryptoService.ts` |
| Module-level constants | `UPPER_SNAKE_CASE` | `ARGON2_MEMORY`, `SALT_LENGTH` |
| Component props | `{ComponentName}Props` interface | `VaultItemCardProps` |
| Context types | `{Name}ContextType` interface | `VaultContextType` |
| Types/interfaces | `PascalCase` | `VaultItemData`, `LanguageCode` |

### Functions and Exports

- **Services**: Named `export function` declarations (never default, never arrow).
- **Components**: Named `export function ComponentName(props)` — never default export.
- **Pages**: `export default function PageName()` — pages are the only default exports.
- **Hooks**: Named `export function useHookName()`.
- **Private helpers in modules**: Plain `function` declarations (not arrow).
- **Helpers inside components**: Arrow `const` (`const handleClick = () => { ... }`).

### Types and Interfaces

- Service-level types: Defined at the bottom of the file with a `// ============ Type Definitions ============` section banner.
- Component prop types: Defined directly above the component.
- Context types: Defined at the top of the file, after imports.
- Prefer `export interface` for object shapes. Use `export type` for unions and aliases.
- Inline return types are acceptable for small objects: `(): { valid: boolean; error?: string }`.

### React Component Structure

Follow this ordering inside components:

1. Context hooks (`useAuth()`, `useVault()`)
2. Library hooks (`useTranslation()`, `useNavigate()`)
3. State hooks (`useState`)
4. Derived values / computed state
5. Side effects (`useEffect`)
6. Handler functions (as `const` arrow functions)
7. Early returns for guards/loading/locked states
8. JSX return

### Context Provider Pattern

```ts
const MyContext = createContext<MyContextType | undefined>(undefined);

export function MyProvider({ children }: { children: ReactNode }) {
    // ... state, effects, callbacks ...
    return <MyContext.Provider value={...}>{children}</MyContext.Provider>;
}

export function useMy() {
    const context = useContext(MyContext);
    if (context === undefined) {
        throw new Error('useMy must be used within a MyProvider');
    }
    return context;
}
```

### Error Handling

- **Services**: Let errors propagate naturally from Web Crypto APIs. Use guard-throws for invalid input (`throw new Error('...')`). For fallible operations, return `{ error: Error | null }`.
- **Context actions**: Wrap in try/catch, `console.error` the error, and return `{ error: Error | null }`.
- **Components**: try/catch with toast notifications for user-facing errors. Use bare `catch {` (no variable) when the error object is unused.
- **Tests**: `expect(error).toBeNull()` for error checks; `throw new Error(...)` in `beforeAll` for fatal setup failures.

### Comments and Documentation

- Every file gets a `@fileoverview` JSDoc block describing its purpose.
- Every exported function gets a JSDoc comment with `@param`, `@returns`, and optionally `@throws`.
- Use section banners (`// ============ Section Name ============`) to separate logical groups.
- Inline comments explain "why", not "what".

### CSS and Styling

- Tailwind CSS utility classes via `className`. Use `cn()` from `@/lib/utils` for conditional classes.
- Design tokens via CSS custom properties (defined in `src/index.css`), referenced as `hsl(var(--primary))` in Tailwind config.
- Dark mode via the `class` strategy (`darkMode: ["class"]`).
- Do not hand-edit files in `src/components/ui/` — these are shadcn/ui generated.

## Testing Guidelines

- Framework: Vitest + Testing Library + jsdom.
- Property-based testing: `fast-check` is available and used for crypto round-trip tests.
- Global setup in `src/test/setup.ts` provides mocks for Web Crypto API, IndexedDB, Clipboard API, and console filtering.
- Structure tests with `describe` / `it` / `expect`. Import from `vitest` explicitly in test files.
- Use descriptive `it` strings: `"should preserve data through encrypt-decrypt round-trip"`.
- Timeouts for slow async tests: pass as second arg to `it("...", async () => {}, 60000)`.
- Cover new logic in services and hooks. Cover critical UI flows in components.

## Security and Configuration

- **Never commit secrets**. The `.env` file is gitignored. Copy `env.example` to `.env` and set `VITE_SUPABASE_PROJECT_ID`, `VITE_SUPABASE_PUBLISHABLE_KEY`, `VITE_SUPABASE_URL`, `VITE_SITE_URL`.
- The Vite config applies comprehensive security headers (CSP, HSTS, X-Frame-Options, Permissions-Policy) — review `vite.config.ts` before modifying.
- TypeScript is intentionally configured with `strict: false` and `noImplicitAny: false` in `tsconfig.app.json`.
- WASM support is enabled via `vite-plugin-wasm` and `vite-plugin-top-level-await` for the `argon2id` dependency.
- Node.js version: `>=20.19.0` (pinned at `22.12.0` via `.node-version`).

## Commit and PR Guidelines

- Short, imperative commit messages (e.g., `fix vault unlock race condition`, `add TOTP export feature`).
- Create a git commit after each completed logical change set (small, atomic commits).
- Do not push directly to the owner's working branch or default branches (`main`/`master`). Create a feature branch first (for example `feature/support-admin-hardening`) and push that branch.
- Open a PR from the feature branch into the target branch instead of direct branch pushes.
- PRs must include: summary of behavioral changes, linked issue if applicable, screenshots for UI changes, notes for env/migration changes.
- Run `npm run lint` and `npm run test` before pushing.

## Supabase

- Project ID: `lcrtadxlojaucwapgzmy`.
- SQL migrations in `supabase/migrations/`.
- Edge Functions in `supabase/functions/` (checkout, subscriptions, Stripe webhook, email, family/emergency access invitations).
- Database types are generated in `src/integrations/supabase/types.ts`.
