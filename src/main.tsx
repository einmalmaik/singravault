// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { isTauriRuntime } from "@/platform/runtime";
import { installDesktopConsoleMirroring } from "@/services/desktopDiagnosticsService";

import { initPremium } from '@singra/premium';

if (isTauriRuntime()) {
  installDesktopConsoleMirroring();
}

initPremium();

if (isTauriRuntime()) {
  purgeDesktopServiceWorkers();
}

// Dev should always load the live Vite graph, never a stale PWA shell.
if (import.meta.env.DEV && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.getRegistrations().then((registrations) => {
      registrations.forEach((registration) => {
        registration.unregister().catch(() => undefined);
      });
    }).catch(() => undefined);

    if ("caches" in window) {
      caches.keys().then((cacheKeys) => {
        cacheKeys.forEach((cacheKey) => {
          caches.delete(cacheKey).catch(() => undefined);
        });
      }).catch(() => undefined);
    }
  });
}

if (import.meta.env.PROD && !isTauriRuntime() && "serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker
      .register("/sw.js")
      .then((registration) => {
        registration.update().catch(() => undefined);

        registration.addEventListener("updatefound", () => {
          const installing = registration.installing;
          if (!installing) {
            return;
          }

          installing.addEventListener("statechange", () => {
            if (installing.state === "installed" && navigator.serviceWorker.controller) {
              console.info("A new service worker version is waiting to activate.");
            }
          });
        });
      })
      .catch((err) => {
        console.error("Service worker registration failed:", err);
      });
  });
}

createRoot(document.getElementById("root")!).render(<App />);

function purgeDesktopServiceWorkers() {
  if (typeof window === "undefined") {
    return;
  }

  window.addEventListener("load", () => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        registrations.forEach((registration) => {
          registration.unregister().catch(() => undefined);
        });
      }).catch(() => undefined);
    }

    if ("caches" in window) {
      caches.keys().then((cacheKeys) => {
        cacheKeys.forEach((cacheKey) => {
          caches.delete(cacheKey).catch(() => undefined);
        });
      }).catch(() => undefined);
    }
  }, { once: true });
}
