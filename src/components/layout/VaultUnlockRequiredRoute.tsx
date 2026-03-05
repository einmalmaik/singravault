// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Unlock Required Route Wrapper
 *
 * Ensures route content only mounts when the vault encryption key is present
 * in memory. Redirects locked/setup states to /vault.
 */

import { Navigate, useLocation } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { useVault } from '@/contexts/VaultContext';

interface VaultUnlockRequiredRouteProps {
    children: React.ReactNode;
}

export function VaultUnlockRequiredRoute({ children }: VaultUnlockRequiredRouteProps) {
    const { t } = useTranslation();
    const location = useLocation();
    const { isLocked, isSetupRequired, isLoading } = useVault();

    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="text-center space-y-4">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
                    <p className="text-muted-foreground">{t('common.loading', { defaultValue: 'Loading...' })}</p>
                </div>
            </div>
        );
    }

    if (isSetupRequired || isLocked) {
        return <Navigate to="/vault" state={{ from: location }} replace />;
    }

    return <>{children}</>;
}
