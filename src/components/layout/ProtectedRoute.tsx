// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview ProtectedRoute Wrapper
 *
 * Ensures components only mount when authentication state is fully established
 * and verified. Prevents race conditions with API requests.
 */

import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useTranslation } from "react-i18next";

interface ProtectedRouteProps {
    children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
    const { user, loading, authReady, isOfflineSession } = useAuth();
    const location = useLocation();
    const { t } = useTranslation();
    const [showSpinner, setShowSpinner] = useState(false);

    // Prevent immediate spinner flash for fast auth resolves
    useEffect(() => {
        const timer = setTimeout(() => setShowSpinner(true), 150);
        return () => clearTimeout(timer);
    }, []);

    // 1. Wait until AuthContext signals it is fully ready
    if (!authReady || loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                {showSpinner && (
                    <div className="text-center space-y-4">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
                        <p className="text-muted-foreground">{t("common.loading", { defaultValue: "Loading..." })}</p>
                    </div>
                )}
            </div>
        );
    }

    // 2. Auth is resolved. If there's no user, redirect to login page
    if (!user) {
        // Save the attempted URL for redirecting after login, if needed
        const redirectTarget = `${location.pathname}${location.search}${location.hash}`;
        return (
            <Navigate
                to={`/auth?redirect=${encodeURIComponent(redirectTarget)}`}
                state={{ from: location }}
                replace
            />
        );
    }

    if (isOfflineSession && !location.pathname.startsWith("/vault")) {
        return <Navigate to="/vault" replace />;
    }

    // 3. Auth is ready and user is defined: render protected content
    return <>{children}</>;
}
