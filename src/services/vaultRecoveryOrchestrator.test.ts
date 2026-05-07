import { describe, expect, it } from 'vitest';

import * as recoveryOrchestrator from './vaultRecoveryOrchestrator';

describe('vaultRecoveryOrchestrator', () => {
  it('keeps recovery orchestration read-only for quarantine resolution', () => {
    const exports = recoveryOrchestrator as Record<string, unknown>;

    expect(exports.restoreQuarantinedVaultItem).toBeUndefined();
    expect(exports.deleteQuarantinedVaultItem).toBeUndefined();
    expect(exports.acceptMissingQuarantinedVaultItem).toBeUndefined();
  });
});
