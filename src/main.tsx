// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";
import { isTauriRuntime } from "@/platform/runtime";

import { initPremium } from '@singra/premium';

// IMMEDIATELY capture hash before any router/library clears it
if (typeof window !== 'undefined' && window.location.hash.includes('access_token=')) {
  sessionStorage.setItem('tauri_login_hash', window.location.hash);
}

initPremium();

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
