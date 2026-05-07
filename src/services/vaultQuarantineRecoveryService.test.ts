import { describe, expect, it } from 'vitest';

import { buildQuarantineResolutionMap } from './vaultQuarantineRecoveryService';

describe('vaultQuarantineRecoveryService', () => {
  it('does not expose a generic accept-missing quarantine action', () => {
    const resolution = buildQuarantineResolutionMap(
      [{ id: 'item-1', reason: 'missing_on_server', updatedAt: null }],
      {},
    );

    expect(resolution['item-1']).toMatchObject({
      canRestore: false,
      canDelete: false,
      hasTrustedLocalCopy: false,
    });
    expect(Object.prototype.hasOwnProperty.call(resolution['item-1'], 'canAcceptMissing')).toBe(false);
  });
});
