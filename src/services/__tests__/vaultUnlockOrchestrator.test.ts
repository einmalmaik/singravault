import { beforeEach, describe, expect, it, vi } from 'vitest';

import { enforceVaultTwoFactorBeforeKeyRelease } from '../vaultUnlockOrchestrator';
import { getTwoFactorRequirement } from '../twoFactorService';
import { getOfflineVaultTwoFactorRequirement } from '../offlineVaultService';

vi.mock('../offlineVaultService', () => ({
  getOfflineVaultTwoFactorRequirement: vi.fn(),
  isAppOnline: vi.fn(() => true),
  saveOfflineVaultTwoFactorRequirement: vi.fn(),
}));

vi.mock('../twoFactorService', () => ({
  getTwoFactorRequirement: vi.fn(),
}));

describe('vaultUnlockOrchestrator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not require 2FA when vault 2FA is not enabled', async () => {
    vi.mocked(getTwoFactorRequirement).mockResolvedValue({
      context: 'vault_unlock',
      status: 'loaded',
      required: false,
    });

    const result = await enforceVaultTwoFactorBeforeKeyRelease({ userId: 'user-1' });

    expect(result.error).toBeNull();
  });

  it('requires an explicit verifier when vault 2FA is enabled', async () => {
    vi.mocked(getTwoFactorRequirement).mockResolvedValue({
      context: 'vault_unlock',
      status: 'loaded',
      required: true,
    });

    const result = await enforceVaultTwoFactorBeforeKeyRelease({ userId: 'user-1' });

    expect(result.error?.message).toContain('Vault 2FA verification required');
  });

  it('keeps offline unknown 2FA status fail-closed', async () => {
    const offlineVaultService = await import('../offlineVaultService');
    vi.mocked(offlineVaultService.isAppOnline).mockReturnValue(false);
    vi.mocked(getOfflineVaultTwoFactorRequirement).mockResolvedValue(null);

    const result = await enforceVaultTwoFactorBeforeKeyRelease({ userId: 'user-1' });

    expect(result.error?.message).toContain('Vault 2FA status is not cached');
  });
});
