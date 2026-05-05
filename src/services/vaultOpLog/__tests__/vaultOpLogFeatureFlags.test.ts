// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import {
  isVaultOpLogRepositoryEnabled,
  isVaultOpLogShadowModeEnabled,
  isVaultOpLogPhase9UIEnabled,
} from '../vaultOpLogFeatureFlags';

describe('vaultOpLogFeatureFlags', () => {
  it('keeps the operation-log repository path enabled', () => {
    expect(isVaultOpLogRepositoryEnabled()).toBe(true);
  });

  it('keeps shadow mode disabled as a diagnostic-only stub', () => {
    expect(isVaultOpLogShadowModeEnabled()).toBe(false);
  });

  it('keeps the security UI enabled', () => {
    expect(isVaultOpLogPhase9UIEnabled()).toBe(true);
  });

  it('does not let shadow mode reactivate old runtime logic', () => {
    expect(isVaultOpLogRepositoryEnabled()).toBe(true);
    expect(isVaultOpLogPhase9UIEnabled()).toBe(true);
    expect(isVaultOpLogShadowModeEnabled()).toBe(false);
  });
});
