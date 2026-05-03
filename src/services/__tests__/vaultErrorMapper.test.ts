import { describe, expect, it } from 'vitest';

import { mapVaultErrorToUiSafeError } from '../vaultErrorMapper';

describe('vaultErrorMapper', () => {
  it('does not map missing Device Key to 2FA', () => {
    const mapped = mapVaultErrorToUiSafeError(new Error('Device Key missing for this vault'));

    expect(mapped.code).toBe('device_key_missing');
  });

  it('does not map integrity blocks to wrong password', () => {
    const mapped = mapVaultErrorToUiSafeError(new Error('Vault integrity verification failed.'));

    expect(mapped.code).toBe('integrity_blocked');
  });

  it('maps vault 2FA only from vault 2FA errors', () => {
    const mapped = mapVaultErrorToUiSafeError(new Error('Vault 2FA verification required before unlock.'));

    expect(mapped.code).toBe('two_factor_required');
  });
});
