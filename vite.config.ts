import { defineConfig, type PluginContext } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import fs from "fs";
import { componentTagger } from "lovable-tagger";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import { VitePWA } from "vite-plugin-pwa";

const GITHUB_LATEST_RELEASE_URL = "https://api.github.com/repos/einmalmaik/singravault/releases/latest";

async function resolveAppVersion(mode: string, packageVersion: string): Promise<{ version: string; source: string }> {
  const explicitVersion = process.env.SINGRA_VAULT_VERSION?.trim();
  if (explicitVersion) {
    return { version: explicitVersion.replace(/^v/i, ""), source: "env:SINGRA_VAULT_VERSION" };
  }

  if (mode === "development") {
    return { version: "dev build", source: "development-mode" };
  }

  try {
    const response = await fetch(GITHUB_LATEST_RELEASE_URL, {
      headers: {
        "Accept": "application/vnd.github+json",
        "User-Agent": "singra-vault-build",
      },
    });

    if (!response.ok) {
      return { version: "unreleased", source: `github-latest-release-http-${response.status}` };
    }

    const release = await response.json() as { tag_name?: unknown; name?: unknown };
    const tag = typeof release.tag_name === "string" ? release.tag_name.trim() : "";
    const normalizedTag = tag.replace(/^v/i, "");

    if (/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(normalizedTag)) {
      return { version: normalizedTag, source: "github-latest-release" };
    }
  } catch {
    return { version: "unreleased", source: "github-latest-release-unavailable" };
  }

  return { version: "unreleased", source: packageVersion ? "github-latest-release-invalid-tag" : "package-version-missing" };
}

function buildContentSecurityPolicy(mode: string, delivery: "header" | "meta" = "header") {
  const dev = mode === "development";
  const scriptSrc = dev
    ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    : "script-src 'self' 'wasm-unsafe-eval'";
  const workerSrc = "worker-src 'self' blob:";
  const connectSrc = dev
    ? "connect-src 'self' ws: wss: http: https:"
    : "connect-src 'self' https://*.supabase.co https://api.pwnedpasswords.com wss://*.supabase.co";
  const imgSrc = dev
    ? "img-src 'self' data: blob: https:"
    : "img-src 'self' data: blob:";
  const fontSrc = dev
    ? "font-src 'self' data: https:"
    : "font-src 'self' data:";

  return [
    "default-src 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline'",
    imgSrc,
    fontSrc,
    workerSrc,
    connectSrc,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    ...(delivery === "header" ? ["frame-ancestors 'none'"] : []),
  ].join("; ");
}

function getSecurityHeaders(mode: string) {
  const dev = mode === "development";

  return {
    "Content-Security-Policy": buildContentSecurityPolicy(mode),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    "X-Permitted-Cross-Domain-Policies": "none",
    ...(dev ? { "Cache-Control": "no-store" } : {}),
  };
}

function cspMetaPlugin(mode: string) {
  return {
    name: "singra-csp-meta",
    transformIndexHtml() {
      return [{
        tag: "meta",
        attrs: {
          "http-equiv": "Content-Security-Policy",
          content: buildContentSecurityPolicy(mode, "meta"),
        },
        injectTo: "head-prepend" as const,
      }];
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig(async ({ mode }) => {
  if (mode !== "development" && process.env.VITE_DEV_TEST_ACCOUNT_UI === "true") {
    throw new Error("VITE_DEV_TEST_ACCOUNT_UI must not be enabled in production builds.");
  }
  if (mode !== "development" && process.env.SINGRA_DEV_TEST_ACCOUNT_ENABLED === "true") {
    throw new Error("SINGRA_DEV_TEST_ACCOUNT_ENABLED must not be enabled in production builds.");
  }

  const packageJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, "package.json"), "utf-8")) as {
    version?: string;
  };
  const appVersion = await resolveAppVersion(mode, packageJson.version ?? "");
  const securityHeaders = getSecurityHeaders(mode);
  const isDev = mode === "development";
  const tauriDevHost = process.env.TAURI_DEV_HOST;
  const isTauriBuild = Boolean(process.env.TAURI_ENV_PLATFORM);
  const shouldEnablePwa = !isTauriBuild;

  const premiumSrc = path.resolve(__dirname, "../singra-premium/src");
  const coreSrc = path.resolve(__dirname, "./src");
  const premiumDevEntry = path.resolve(__dirname, "../singra-premium/src/extensions/initPremium.ts");
  const premiumInstalledEntry = path.resolve(__dirname, "./node_modules/@singra/premium/dist/initPremium.mjs");
  const premiumStubEntry = path.resolve(__dirname, "./src/extensions/premiumStub.ts");
  const isPremiumDisabled = process.env.SINGRA_DISABLE_PREMIUM === "true";
  const hasPremiumDevRepo = fs.existsSync(premiumDevEntry);
  const hasInstalledPremiumPackage = fs.existsSync(premiumInstalledEntry);
  // Keep local development and local desktop builds on the same premium code path.
  // When the sibling repo exists, it is the source of truth; packaged installs and CI
  // still fall back to the installed package if no sibling checkout is present.
  const shouldUsePremiumSource = !isPremiumDisabled && hasPremiumDevRepo;
  const premiumEntry = isPremiumDisabled
    ? premiumStubEntry
    : shouldUsePremiumSource
    ? premiumDevEntry
    : hasInstalledPremiumPackage
      ? premiumInstalledEntry
      : premiumStubEntry;

  function premiumResolvePlugin() {
    const coreSrcNormalized = coreSrc.replace(/\\/g, "/");
    const premiumSrcNormalized = premiumSrc.replace(/\\/g, "/");
    const moduleExtensions = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"];
    const coreResolverImporter = path.resolve(__dirname, "src/main.tsx");

    const findExistingModulePath = (basePath: string) => {
      for (const ext of moduleExtensions) {
        const candidate = `${basePath}${ext}`;
        if (fs.existsSync(candidate)) {
          return candidate;
        }
      }

      return null;
    };

    const resolveCoreModuleId = async (context: PluginContext, modulePath: string) => {
      const relativeToCore = path.relative(coreSrc, modulePath).replace(/\\/g, "/");
      const resolved = await context.resolve(`@/${relativeToCore}`, coreResolverImporter, {
        skipSelf: true,
      });

      return resolved?.id ?? modulePath;
    };

    const resolveAliasedBasePath = (importSource: string) => {
      if (importSource.startsWith("@/")) {
        return path.join(coreSrc, importSource.slice(2));
      }

      if (importSource.startsWith("/src/")) {
        return path.join(__dirname, importSource.slice(1));
      }

      return null;
    };

    return {
      name: "premium-resolve",
      enforce: "pre" as const,
      async resolveId(this: PluginContext, source: string, importer: string | undefined) {
        if (!importer) return null;

        const normalizedSource = source.replace(/\\/g, "/");
        const normalizedImporter = importer.replace(/\\/g, "/");
        const isPremiumImporter = normalizedImporter.includes(premiumSrcNormalized + "/");

        if (isPremiumImporter) {
          const aliasedBasePath = resolveAliasedBasePath(source);

          if (aliasedBasePath) {
            const coreModulePath = findExistingModulePath(aliasedBasePath);
            if (coreModulePath) {
              return resolveCoreModuleId(this, coreModulePath);
            }

            const relativeToCore = path.relative(coreSrc, aliasedBasePath);
            const premiumModulePath = findExistingModulePath(path.join(premiumSrc, relativeToCore));
            if (premiumModulePath) {
              return premiumModulePath;
            }
          }
        }

        if (normalizedSource.startsWith(coreSrcNormalized + "/")) {
          const coreModulePath = findExistingModulePath(source);

          if (!coreModulePath) {
            const relativePath = normalizedSource.slice(coreSrcNormalized.length);
            const premiumModulePath = findExistingModulePath(path.join(premiumSrc, relativePath));
            if (premiumModulePath) {
              return premiumModulePath;
            }
          } else if (isPremiumImporter) {
            return resolveCoreModuleId(this, coreModulePath);
          }
        }

        if ((source.startsWith("./") || source.startsWith("../")) && isPremiumImporter) {
          const importerDir = path.dirname(importer);
          const resolvedAbsolute = path.resolve(importerDir, source);
          const localModulePath = findExistingModulePath(resolvedAbsolute);

          if (!localModulePath) {
            const importerRelativeToSrc = path.relative(premiumSrc, importer);
            const importerDirInSrc = path.dirname(importerRelativeToSrc);
            const targetRelative = path.join(importerDirInSrc, source);
            const coreModulePath = findExistingModulePath(path.join(coreSrc, targetRelative));

            if (coreModulePath) {
              return resolveCoreModuleId(this, coreModulePath);
            }
          }
        }

        if (!source.startsWith(".") && !source.startsWith("/") && !source.startsWith("@/")) {
          if (normalizedImporter.includes("singra-premium/")) {
            const resolved = await this.resolve(source, path.resolve(__dirname, "src/main.tsx"), { skipSelf: true });
            if (resolved) return resolved;
          }
        }

        return null;
      },
    };
  }

  return {
    server: {
      host: tauriDevHost || "::",
      port: 8080,
      strictPort: isTauriBuild,
      headers: securityHeaders,
      hmr: {
        overlay: false,
        ...(tauriDevHost ? { protocol: "ws", host: tauriDevHost, port: 8080 } : {}),
      },
      watch: {
        ignored: ["**/src-tauri/**"],
      },
      fs: {
        allow: [coreSrc, premiumSrc, path.resolve(__dirname, "node_modules")],
        strict: false,
      },
    },
    preview: {
      headers: securityHeaders,
    },
    plugins: [
      wasm(),
      topLevelAwait(),
      cspMetaPlugin(mode),
      react(),
      isDev && componentTagger(),
      shouldUsePremiumSource && premiumResolvePlugin(),
      shouldEnablePwa && VitePWA({
        strategies: "injectManifest",
        srcDir: "src",
        filename: "sw.ts",
        manifest: false,
        injectRegister: "script",
        injectManifest: {
          globPatterns: ["**/*.{js,css,html,ico,png,svg,webmanifest}"],
          maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        },
        devOptions: {
          enabled: false,
        },
      }),
    ].filter(Boolean),
    resolve: {
      dedupe: ["react", "react-dom", "react-router-dom"],
      alias: {
        "@": path.resolve(__dirname, "./src"),
        "@singra/premium": premiumEntry,
      },
    },
    build: {
      target: "esnext",
    },
    define: {
      __APP_VERSION__: JSON.stringify(appVersion.version),
      __APP_VERSION_SOURCE__: JSON.stringify(appVersion.source),
    },
  };
});
