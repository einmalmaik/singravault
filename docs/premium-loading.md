# Optional Premium Loading

The core repository must remain installable and buildable without the private `@singra/premium` package.

## Resolution Order

1. In development, if the sibling repository `../singra-premium` exists, Vite resolves `@singra/premium` to that source entry for side-by-side work.
2. Otherwise, if `node_modules/@singra/premium/dist/initPremium.mjs` exists, Vite resolves to the installed package.
3. If neither exists, Vite resolves `@singra/premium` to the local no-op stub at `src/extensions/premiumStub.ts`.

## Expected Workflows

- Core-only self-hosting:
  - `npm install`
  - `npm run build`
  - deploy normally

- Core-only local development with sibling premium repo present:
  - set `SINGRA_DISABLE_PREMIUM=true`
  - start Vite or Tauri dev normally
  - the resolver forces the local stub and skips premium registration

- Premium-enabled deployment:
  - install `@singra/premium` into the root project
  - `npm run build`
  - premium features register automatically via `initPremium()`

## Vercel

The Vercel install step uses `node scripts/vercel-install.mjs`.

- Core-only deployment:
  - do not set `INSTALL_SINGRA_PREMIUM`
- Premium-enabled deployment:
  - set `INSTALL_SINGRA_PREMIUM=true`
  - set `GITHUB_PAT` to a token with access to `einmalmaik/singra-premium`
  - optionally set `SINGRA_PREMIUM_REF=master` or a pinned commit/tag

When `INSTALL_SINGRA_PREMIUM=true`, the install script injects `@singra/premium` into the temporary Vercel build workspace before running `npm install`.
