// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { VaultOpLogSecurityModeBanner } from '../VaultOpLogSecurityModeBanner';
import type { VaultSecurityMode } from '@/services/vaultOpLog/vaultSecurityStates';

describe('VaultOpLogSecurityModeBanner', () => {
  it.each([
    ['normal', 'Tresor verifiziert'],
    ['restricted', 'Eingeschränkter Modus'],
    ['safeMode', 'Safe Mode'],
    ['safeModeRecommended', 'Safe Mode'],
    ['lockedCritical', 'Kritische Sperre'],
  ] as [VaultSecurityMode, string][])('renders %s banner with expected title', (mode, expectedTitle) => {
    render(<VaultOpLogSecurityModeBanner mode={mode} />);
    expect(screen.getByText(expectedTitle)).toBeInTheDocument();
  });

  it('does not render plaintext secrets', () => {
    render(<VaultOpLogSecurityModeBanner mode="restricted" />);
    expect(screen.queryByText(/password/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secret/i)).not.toBeInTheDocument();
  });
});
