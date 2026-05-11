import { useEffect } from 'react';

import { loadVaultOpLogDeviceIdentity } from '@/services/vaultOpLog/vaultOpLogDeviceStore';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';
import type { LocalVaultState } from '@/services/vaultOpLog/vaultStateMachine';

interface VaultRevokedDeviceAutoLockInput {
  readonly isLocked: boolean;
  readonly localVaultState: LocalVaultState | null;
  readonly vaultMigrationStatus: VaultMigrationRolloutStatus | null;
  readonly lock: () => void;
}

export function useVaultRevokedDeviceAutoLock({
  isLocked,
  localVaultState,
  lock,
  vaultMigrationStatus,
}: VaultRevokedDeviceAutoLockInput): void {
  useEffect(() => {
    if (isLocked || vaultMigrationStatus !== 'verified' || !localVaultState) {
      return;
    }

    const deviceIdentity = loadVaultOpLogDeviceIdentity();
    if (!deviceIdentity) {
      return;
    }

    const currentDevice = localVaultState.trustedDevicesById.get(deviceIdentity.deviceId);
    if (currentDevice?.status === 'revoked') {
      lock();
    }
  }, [isLocked, localVaultState, lock, vaultMigrationStatus]);
}
