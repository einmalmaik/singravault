import { useEffect } from 'react';

import {
  clearVaultOpLogDeviceIdentity,
  loadVaultOpLogDeviceIdentity,
} from '@/services/vaultOpLog/vaultOpLogDeviceStore';
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
      // The revoked identity must not keep re-locking the next unlock attempt.
      // Clearing only non-secret identity metadata lets the device re-enter the
      // untrusted pairing/recovery flow; it does not recreate trust or expose
      // the non-extractable private signing key.
      clearVaultOpLogDeviceIdentity();
      lock();
    }
  }, [isLocked, localVaultState, lock, vaultMigrationStatus]);
}
