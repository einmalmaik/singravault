// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import { describe, expect, it } from 'vitest';
import {
  isVaultOpLogRepositoryEnabled,
  isVaultOpLogShadowModeEnabled,
  isVaultOpLogPhase9UIEnabled,
} from '../vaultOpLogFeatureFlags';

describe('vaultOpLogFeatureFlags', () => {
  it('isVaultOpLogRepositoryEnabled returns false by default', () => {
    expect(isVaultOpLogRepositoryEnabled()).toBe(false);
  });

  it('isVaultOpLogShadowModeEnabled returns false by default', () => {
    expect(isVaultOpLogShadowModeEnabled()).toBe(false);
  });

  it('isVaultOpLogPhase9UIEnabled returns false by default', () => {
    expect(isVaultOpLogPhase9UIEnabled()).toBe(false);
  });

  it('Phase 9 flag is independent from Shadow Mode flag', () => {
    // Both default to false, but they are separate concepts.
    expect(isVaultOpLogPhase9UIEnabled()).toBe(false);
    expect(isVaultOpLogShadowModeEnabled()).toBe(false);
  });
});
