// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

// Premium extensions disabled for Core-only testing
// import { initPremium } from "@/extensions/initPremium";
// initPremium();

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js')
      .then((registration) => {
        registration.update().catch(() => undefined);

        registration.addEventListener('updatefound', () => {
          const installing = registration.installing;
          if (!installing) {
            return;
          }

          installing.addEventListener('statechange', () => {
            if (installing.state === 'installed' && navigator.serviceWorker.controller) {
              console.info('A new service worker version is waiting to activate.');
            }
          });
        });
      })
      .catch((err) => {
        console.error('Service worker registration failed:', err);
      });
  });
}

createRoot(document.getElementById("root")!).render(<App />);
