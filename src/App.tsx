// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Main App Component
 * 
 * Sets up providers and routing for Singra Vault.
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

// Import i18n configuration
import "@/i18n";

// Pages
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import VaultPage from "./pages/VaultPage";
import SettingsPage from "./pages/SettingsPage";
import PricingPage from "./pages/PricingPage";
import VaultHealthPage from "./pages/VaultHealthPage";
import AuthenticatorPage from "./pages/AuthenticatorPage";
import NotFound from "./pages/NotFound";
import PrivacyPolicy from "./pages/PrivacyPolicy";
import AdminPage from "./pages/AdminPage";
import { CookieConsent } from "./components/CookieConsent";
import { SupportWidget } from "./components/SupportWidget";
import { ProtectedRoute } from "./components/layout/ProtectedRoute";
import Impressum from "./pages/Impressum";
import GrantorVaultPage from "./pages/GrantorVaultPage";
import SecurityWhitepaper from "./pages/SecurityWhitepaper";

const queryClient = new QueryClient();

const App = () => (
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
                <SupportWidget />
                <BrowserRouter>
                  <Routes>
                    <Route path="/" element={<Index />} />
                    <Route path="/auth" element={<Auth />} />
                    <Route path="/vault" element={<ProtectedRoute><VaultPage /></ProtectedRoute>} />
                    <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
                    <Route path="/pricing" element={<PricingPage />} />
                    <Route path="/vault-health" element={<ProtectedRoute><VaultHealthPage /></ProtectedRoute>} />
                    <Route path="/authenticator" element={<ProtectedRoute><AuthenticatorPage /></ProtectedRoute>} />
                    <Route path="/admin" element={<ProtectedRoute><AdminPage /></ProtectedRoute>} />
                    <Route path="/vault/emergency/:id" element={<ProtectedRoute><GrantorVaultPage /></ProtectedRoute>} />
                    <Route path="/security" element={<SecurityWhitepaper />} />
                    <Route path="/privacy" element={<PrivacyPolicy />} />
                    <Route path="/impressum" element={<Impressum />} />
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

export default App;

