import { defineConfig, type PluginContext } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import fs from "fs";
import { componentTagger } from "lovable-tagger";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";
import { VitePWA } from "vite-plugin-pwa";

function getSecurityHeaders(mode: string) {
  const dev = mode === "development";
  const scriptSrc = dev
    ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    : "script-src 'self' 'wasm-unsafe-eval'";
  const workerSrc = "worker-src 'self' blob:";
  const connectSrc = dev
    ? "connect-src 'self' ws: wss: http: https:"
    : "connect-src 'self' https://*.supabase.co wss://*.supabase.co";

  return {
    "Content-Security-Policy": [
      "default-src 'self'",
      scriptSrc,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https:",
      "font-src 'self' data: https:",
      workerSrc,
      connectSrc,
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    "X-Permitted-Cross-Domain-Policies": "none",
    ...(dev ? { "Cache-Control": "no-store" } : {}),
  };
}

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const securityHeaders = getSecurityHeaders(mode);
  const isDev = mode === "development";
  const tauriDevHost = process.env.TAURI_DEV_HOST;
  const isTauriBuild = Boolean(process.env.TAURI_ENV_PLATFORM);

  const premiumSrc = path.resolve(__dirname, "../singra-premium/src");
  const coreSrc = path.resolve(__dirname, "./src");
  const premiumDevEntry = path.resolve(__dirname, "../singra-premium/src/extensions/initPremium.ts");
  const premiumInstalledEntry = path.resolve(__dirname, "./node_modules/@singra/premium/dist/initPremium.mjs");
  const premiumStubEntry = path.resolve(__dirname, "./src/extensions/premiumStub.ts");
  const isPremiumDisabled = process.env.SINGRA_DISABLE_PREMIUM === "true";
  const hasPremiumDevRepo = fs.existsSync(premiumDevEntry);
  const hasInstalledPremiumPackage = fs.existsSync(premiumInstalledEntry);
  const shouldUsePremiumSource =
    !isPremiumDisabled
    && hasPremiumDevRepo
    && (isDev || isTauriBuild || process.env.SINGRA_PREMIUM_SOURCE === "true");
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
      react(),
      isDev && componentTagger(),
      shouldUsePremiumSource && premiumResolvePlugin(),
      VitePWA({
        strategies: "injectManifest",
        srcDir: "src",
        filename: "sw.ts",
        manifest: false,
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
  };
});
