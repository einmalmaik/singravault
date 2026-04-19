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
  const hasPremiumDevRepo = fs.existsSync(premiumDevEntry);
  const hasInstalledPremiumPackage = fs.existsSync(premiumInstalledEntry);
  const premiumEntry = isDev && hasPremiumDevRepo
    ? premiumDevEntry
    : hasInstalledPremiumPackage
      ? premiumInstalledEntry
      : premiumStubEntry;

  /**
   * Dev-only Vite plugin: After Vite's alias resolution converts @/ to the core
   * src/ path, this plugin checks if the resolved file actually exists in core.
   * If not (because it was extracted to the premium repo), it redirects to the
   * premium repo's src/ directory. Core files (like registry.ts) still resolve
   * normally because they exist in core.
   */
  function premiumResolvePlugin() {
    const coreSrcNormalized = coreSrc.replace(/\\/g, "/");
    const premiumSrcNormalized = premiumSrc.replace(/\\/g, "/");

    return {
      name: "premium-resolve",
      enforce: "pre" as const,
      async resolveId(this: PluginContext, source: string, importer: string | undefined) {
        if (!importer) return null;

        // Normalize the source path
        const normalizedSource = source.replace(/\\/g, "/");
        const normalizedImporter = importer.replace(/\\/g, "/");

        // Case 1: Source is already an absolute path pointing into core src/
        // This happens when Vite's alias resolution has already converted @/ → core src path
        if (normalizedSource.startsWith(coreSrcNormalized + "/")) {
          // Check if the file exists in core
          const exts = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"];
          const existsInCore = exts.some(ext => fs.existsSync(source + ext));

          if (!existsInCore) {
            // Try the premium repo instead
            const relativePath = normalizedSource.slice(coreSrcNormalized.length);
            for (const ext of exts) {
              const premiumCandidate = path.join(premiumSrc, relativePath + ext);
              if (fs.existsSync(premiumCandidate)) {
                return premiumCandidate;
              }
            }
          }
        }

        // Case 2: Relative import from a file inside the premium repo
        // e.g. duressService.ts (in premium) does `import './cryptoService'`
        // Vite resolves this relative to the premium file's directory, but
        // cryptoService.ts lives in core. Redirect to core's equivalent path.
        if (source.startsWith("./") || source.startsWith("../")) {
          if (normalizedImporter.includes("singra-premium/src/")) {
            const importerDir = path.dirname(importer);
            const resolvedAbsolute = path.resolve(importerDir, source);
            const exts = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"];
            const existsLocally = exts.some(ext => fs.existsSync(resolvedAbsolute + ext));

            if (!existsLocally) {
              // Map the premium path to the equivalent core path
              const premiumSrcIndex = normalizedImporter.indexOf("singra-premium/src/");
              if (premiumSrcIndex !== -1) {
                const importerRelativeToSrc = normalizedImporter.slice(premiumSrcIndex + "singra-premium/src/".length);
                const importerDirInSrc = path.dirname(importerRelativeToSrc);
                const targetRelative = path.join(importerDirInSrc, source).replace(/\\/g, "/");
                for (const ext of exts) {
                  const coreCandidate = path.join(coreSrc, targetRelative + ext);
                  if (fs.existsSync(coreCandidate)) {
                    return coreCandidate;
                  }
                }
              }
            }
          }
        }

        // Case 3: Bare module imports from premium repo files (e.g. 'react', 'lucide-react')
        // These need to resolve from the core repo's node_modules
        if (!source.startsWith(".") && !source.startsWith("/") && !source.startsWith("@/")) {
          if (normalizedImporter.includes("singra-premium/")) {
            // Re-resolve the same import as if it came from main.tsx (inside core)
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
        // Allow serving files from the sibling premium repo
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
      isDev && hasPremiumDevRepo && premiumResolvePlugin(),
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
