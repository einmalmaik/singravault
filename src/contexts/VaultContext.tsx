// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { createContext, useContext, type ReactNode } from 'react';
import { useVaultProviderActions } from './vault/useVaultProviderActions';
import type { VaultContextType } from './vault/vaultContextTypes';

const VaultContext = createContext<VaultContextType | undefined>(undefined);

interface VaultProviderProps {
    children: ReactNode;
}

export function VaultProvider({ children }: VaultProviderProps) {
    const value = useVaultProviderActions();

    return (
        <VaultContext.Provider value={value}>
            {children}
        </VaultContext.Provider>
    );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useVault() {
    const context = useContext(VaultContext);
    if (context === undefined) {
        throw new Error('useVault must be used within a VaultProvider');
    }
    return context;
}

export type { VaultContextType, VaultUnlockOptions } from './vault/vaultContextTypes';
