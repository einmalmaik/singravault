// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Main App Component — Open Core Architecture
 *
 * Core routes are always available. Premium routes are loaded
 * dynamically via the Extension Registry.
 */

import { HelmetProvider } from "react-helmet-async";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import { ThemeProvider } from "@/contexts/ThemeProvider";
import { AuthProvider } from "@/contexts/AuthContext";
import { VaultProvider } from "@/contexts/VaultContext";
import { SubscriptionProvider } from "@/contexts/SubscriptionContext";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";
import { CookieConsent } from "./components/CookieConsent";
import { getExtensionRoutes, getExtension, isPremiumActive } from "@/extensions/registry";

// Import i18n configuration
import "@/i18n";

// Core Pages (always available)
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import VaultPage from "./pages/VaultPage";
import SettingsPage from "./pages/SettingsPage";
import AdminPage from "./pages/AdminPage";
import NotFound from "./pages/NotFound";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import Impressum from "./pages/Impressum";
import SecurityWhitepaper from "./pages/SecurityWhitepaper";

const queryClient = new QueryClient();

const App = () => {
  const premiumRoutes = getExtensionRoutes();
  const premiumLoaded = isPremiumActive();
  const SupportWidget = getExtension('layout.support-widget');

  return (
    <HelmetProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <AuthProvider>
            <SubscriptionProvider>
              <VaultProvider>
                <TooltipProvider>
                  <Toaster />
                  <Sonner />
                  <CookieConsent />
                  {SupportWidget && <SupportWidget />}
                  <BrowserRouter>
                    <Routes>
                      {/* Core Routes */}
                      <Route path="/" element={<Index />} />
                      <Route path="/auth" element={<Auth />} />
                      <Route path="/vault" element={<ProtectedRoute><VaultPage /></ProtectedRoute>} />
                      <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
                      {premiumLoaded && <Route path="/admin" element={<ProtectedRoute><AdminPage /></ProtectedRoute>} />}
                      <Route path="/security" element={<SecurityWhitepaper />} />
                      <Route path="/privacy" element={<PrivacyPolicy />} />
                      <Route path="/impressum" element={<Impressum />} />

                      {/* Premium Routes (dynamically registered) */}
                      {premiumRoutes.map((route) => (
                        <Route
                          key={route.path}
                          path={route.path}
                          element={
                            route.protected
                              ? <ProtectedRoute><route.component /></ProtectedRoute>
                              : <route.component />
                          }
                        />
                      ))}

                      {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
                      <Route path="*" element={<NotFound />} />
                    </Routes>
                  </BrowserRouter>
                </TooltipProvider>
              </VaultProvider>
            </SubscriptionProvider>
          </AuthProvider>
        </ThemeProvider>
      </QueryClientProvider>
    </HelmetProvider>
  );
};

export default App;
