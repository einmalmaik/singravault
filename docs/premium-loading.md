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

- Premium-enabled deployment:
  - install `@singra/premium` into the root project
  - `npm run build`
  - premium features register automatically via `initPremium()`
