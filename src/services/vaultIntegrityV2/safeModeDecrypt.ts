import type { VaultItemData } from '@/services/cryptoService';
import type { OfflineVaultSnapshot } from '@/services/offlineVaultService';
import { decryptProductVaultItem } from './productItemEnvelope';

export interface TrustedRecoveryDecryptContext {
  source: 'trusted_recovery_snapshot';
  reason: 'safe_mode_export';
  snapshotId: string;
  userId: string;
  vaultId: string;
}

type TrustedRecoverySnapshotItem = OfflineVaultSnapshot['items'][number];

export class TrustedRecoveryDecryptError extends Error {
  readonly code:
    | 'invalid_recovery_context'
    | 'snapshot_scope_mismatch'
    | 'trusted_recovery_decrypt_failed';

  constructor(code: TrustedRecoveryDecryptError['code']) {
    super(`Trusted recovery decrypt failed: ${code}`);
    this.name = 'TrustedRecoveryDecryptError';
    this.code = code;
  }
}

export async function decryptTrustedRecoverySnapshotItem(input: {
  item: TrustedRecoverySnapshotItem;
  vaultKey: CryptoKey;
  context: TrustedRecoveryDecryptContext;
}): Promise<VaultItemData> {
  assertTrustedRecoveryDecryptContext(input.item, input.context);

  try {
    return await decryptProductVaultItem({
      encryptedData: input.item.encrypted_data,
      vaultKey: input.vaultKey,
      entryId: input.item.id,
    });
  } catch {
    throw new TrustedRecoveryDecryptError('trusted_recovery_decrypt_failed');
  }
}

function assertTrustedRecoveryDecryptContext(
  item: TrustedRecoverySnapshotItem,
  context: TrustedRecoveryDecryptContext,
): void {
  if (
    context.source !== 'trusted_recovery_snapshot'
    || context.reason !== 'safe_mode_export'
    || !context.snapshotId
  ) {
    throw new TrustedRecoveryDecryptError('invalid_recovery_context');
  }

  if (item.user_id !== context.userId || item.vault_id !== context.vaultId) {
    throw new TrustedRecoveryDecryptError('snapshot_scope_mismatch');
  }
}
