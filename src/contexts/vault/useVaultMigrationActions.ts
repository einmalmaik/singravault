import { useCallback } from 'react';
import type { VaultItemData } from '@/services/cryptoService';
import { clearVaultSessionMarkers, markVaultSessionActive } from '@/services/vaultRuntimeFacade';
import { evaluateVaultMigrationGate } from '@/services/vaultOpLog/vaultMigrationRolloutService';
import { runControlledMigration } from '@/services/vaultOpLog/vaultMigrationRuntimeOrchestrator';

type VaultProviderState = ReturnType<typeof import('./useVaultProviderState').useVaultProviderState>;
type ActiveUser = { id: string } | null;
type DecryptLegacyItem = (
  encryptedData: string,
  entryId: string,
) => Promise<{ data: VaultItemData; legacyEnvelopeUsed: boolean; legacyNoAadFallbackUsed: boolean }>;

interface VaultMigrationActionsInput {
  state: VaultProviderState;
  user: ActiveUser;
  decryptItemForLegacyMigration: DecryptLegacyItem;
}

export function useVaultMigrationActions({
  state,
  user,
  decryptItemForLegacyMigration,
}: VaultMigrationActionsInput) {
  const runUserConfirmedMigration = useCallback(async (): Promise<{ error: Error | null }> => {
    if (!user) {
      return { error: new Error('Keine aktive Sitzung verfügbar.') };
    }

    const migrationContext = state.vaultMigrationKeyContext;
    if (!migrationContext?.vaultId || !migrationContext.vaultEncryptionKey) {
      const error = new Error(
        'Die Migration kann nicht gestartet werden. Sperre den Tresor und entsperre ihn erneut.',
      );
      state.setVaultMigrationStatus('preflightFailed');
      state.setVaultMigrationError(error.message);
      state.setVaultMigrationCanStart(false);
      return { error };
    }

    state.setVaultMigrationStatus('running');
    state.setVaultMigrationError(null);
    state.setVaultMigrationCanStart(false);
    state.setIsLocked(true);
    state.setEncryptionKey(null);
    state.setIntegrityMode('migration_required');
    clearVaultSessionMarkers(sessionStorage);

    const result = await runControlledMigration({
      userId: user.id,
      vaultId: migrationContext.vaultId,
      migrationKeyContext: {
        activeKey: migrationContext.activeKey,
        vaultEncryptionKey: migrationContext.vaultEncryptionKey,
      },
      decryptLegacyItem: decryptItemForLegacyMigration,
    });

    if (result.error || !result.success) {
      const error = result.error ?? new Error('Tresor-Migration fehlgeschlagen.');
      state.setVaultMigrationStatus('failed');
      state.setVaultMigrationError(error.message);
      state.setVaultMigrationCanStart(true);
      state.setIsLocked(true);
      state.setEncryptionKey(null);
      state.setIntegrityMode('migration_required');
      return { error };
    }

    const gateAfterMigration = await evaluateVaultMigrationGate({ userId: user.id });
    state.setVaultMigrationStatus(gateAfterMigration.status);
    state.setVaultMigrationError(gateAfterMigration.reason);

    if (!gateAfterMigration.allowNormalUnlock) {
      const error = new Error(
        gateAfterMigration.reason ?? `Tresor-Migration ist noch nicht freigegeben: ${gateAfterMigration.status}`,
      );
      state.setVaultMigrationCanStart(true);
      state.setIsLocked(true);
      state.setEncryptionKey(null);
      state.setIntegrityMode('migration_required');
      return { error };
    }

    state.setEncryptionKey(migrationContext.activeKey);
    state.setIsLocked(false);
    state.setIsDuressMode(false);
    state.setIntegrityMode('healthy');
    state.setIntegrityBlockedReason(null);
    state.setVaultMigrationCanStart(false);
    state.setVaultMigrationKeyContext((existingContext) => {
      existingContext?.vaultEncryptionKey?.fill(0);
      return null;
    });
    state.bumpVaultDataVersion();
    state.setLastActivity(Date.now());
    markVaultSessionActive(sessionStorage);
    state.setPendingSessionRestore(false);

    return { error: null };
  }, [decryptItemForLegacyMigration, state, user]);

  const startVaultMigration = useCallback(async (): Promise<{ error: Error | null }> => {
    return runUserConfirmedMigration();
  }, [runUserConfirmedMigration]);

  const retryVaultMigration = useCallback(async (): Promise<{ error: Error | null }> => {
    return runUserConfirmedMigration();
  }, [runUserConfirmedMigration]);

  return {
    startVaultMigration,
    retryVaultMigration,
  };
}
