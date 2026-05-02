import {
  fetchRemoteOfflineSnapshot,
  getOfflineCredentials,
  getOfflineSnapshot,
  isAppOnline,
  isLikelyOfflineError,
  loadVaultSnapshot,
  saveOfflineSnapshot,
  type OfflineVaultSnapshot,
} from '@/services/offlineVaultService';
import { buildVaultIntegritySnapshot } from '@/services/vaultIntegrityDecisionEngine';
import type { VaultIntegritySnapshot } from '@/services/vaultIntegrityService';
import { isTauriDevUserId, TAURI_DEV_VAULT_ID } from '@/platform/tauriDevMode';
import type { VaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';
import { normalizeVaultProtectionMode } from '@/services/deviceKeyProtectionPolicy';
import { supabase } from '@/integrations/supabase/client';

export type VaultRuntimeSnapshotSource = 'remote' | 'cache' | 'empty';

export interface VaultRuntimeCredentials {
  salt: string;
  verificationHash: string | null;
  kdfVersion: number | null;
  encryptedUserKey: string | null;
  vaultProtectionMode: VaultProtectionMode;
}

export interface VaultRuntimeProfile {
  credentials: VaultRuntimeCredentials | null;
  setupRequired: boolean;
  setupCheckFailed: boolean;
}

export interface CurrentVaultIntegritySnapshot {
  rawSnapshot: OfflineVaultSnapshot;
  integritySnapshot: VaultIntegritySnapshot;
  source: VaultRuntimeSnapshotSource;
}

export async function ensureTauriDevVaultSnapshot(userId: string): Promise<void> {
  if (!isTauriDevUserId(userId)) {
    return;
  }

  const snapshot = await getOfflineSnapshot(userId);
  if (!snapshot || snapshot.vaultId === TAURI_DEV_VAULT_ID) {
    return;
  }

  await saveOfflineSnapshot({
    ...snapshot,
    vaultId: TAURI_DEV_VAULT_ID,
    updatedAt: new Date().toISOString(),
  });
}

export async function loadCachedVaultCredentials(
  userId: string,
): Promise<VaultRuntimeCredentials | null> {
  const cached = await getOfflineCredentials(userId);
  if (!cached) {
    return null;
  }

  return {
    salt: cached.salt,
    verificationHash: cached.verifier,
    kdfVersion: cached.kdfVersion,
    encryptedUserKey: cached.encryptedUserKey,
    vaultProtectionMode: normalizeVaultProtectionMode(cached.vaultProtectionMode),
  };
}

export async function loadCurrentVaultIntegritySnapshot(input: {
  userId: string;
  persistRemoteSnapshot?: boolean;
  preferRemote?: boolean;
  useLocalMutationOverlay?: boolean;
}): Promise<CurrentVaultIntegritySnapshot> {
  const { userId } = input;

  if (isTauriDevUserId(userId) || input.useLocalMutationOverlay) {
    const { snapshot, source } = await loadVaultSnapshot(userId);
    return {
      rawSnapshot: snapshot,
      integritySnapshot: buildVaultIntegritySnapshot(snapshot),
      source,
    };
  }

  if (input.preferRemote || isAppOnline()) {
    try {
      const rawSnapshot = await fetchRemoteOfflineSnapshot(userId, {
        persist: input.persistRemoteSnapshot !== false,
      });

      logIntegritySnapshotSource('remote', rawSnapshot, input);
      return {
        rawSnapshot,
        integritySnapshot: buildVaultIntegritySnapshot(rawSnapshot),
        source: 'remote',
      };
    } catch (error) {
      console.warn('[VaultIntegrity] Remote snapshot load failed.', {
        code: safeSnapshotLoadErrorCode(error),
        preferRemote: input.preferRemote === true,
      });
      if (!isLikelyOfflineError(error)) {
        throw error;
      }
    }
  }

  const { snapshot, source } = await loadVaultSnapshot(userId);
  logIntegritySnapshotSource(source, snapshot, input);
  return {
    rawSnapshot: snapshot,
    integritySnapshot: buildVaultIntegritySnapshot(snapshot),
    source,
  };
}

function logIntegritySnapshotSource(
  source: VaultRuntimeSnapshotSource,
  snapshot: OfflineVaultSnapshot,
  input: {
    persistRemoteSnapshot?: boolean;
    preferRemote?: boolean;
    useLocalMutationOverlay?: boolean;
  },
): void {
  console.info('[VaultIntegrity] Snapshot selected.', {
    source,
    preferRemote: input.preferRemote === true,
    persistRemoteSnapshot: input.persistRemoteSnapshot !== false,
    useLocalMutationOverlay: input.useLocalMutationOverlay === true,
    hasVaultId: Boolean(snapshot.vaultId),
    itemCount: snapshot.items.length,
    categoryCount: snapshot.categories.length,
    remoteRevisionKnown: typeof snapshot.remoteRevision === 'number',
    completenessKind: snapshot.completeness?.kind ?? 'missing',
    completenessReason: snapshot.completeness?.reason ?? 'missing',
    completenessSource: snapshot.completeness?.source ?? 'missing',
  });
}

function safeSnapshotLoadErrorCode(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    const code = String((error as { code?: unknown }).code ?? '');
    if (code) {
      return code.toLowerCase().replace(/[^a-z0-9_:-]/g, '_').slice(0, 80);
    }
  }

  const message = error instanceof Error
    ? error.message.toLowerCase()
    : String((error as { message?: unknown })?.message ?? '').toLowerCase();
  if (message.includes('failed to fetch') || message.includes('network') || message.includes('fetch')) {
    return 'network_unavailable';
  }
  if (message.includes('rollback')) {
    return 'remote_snapshot_rollback';
  }
  return 'snapshot_load_failed';
}

export async function loadRemoteVaultProfile(
  userId: string,
): Promise<VaultRuntimeProfile> {
  const { data: profile, error } = await supabase
    .from('profiles')
    .select('encryption_salt, master_password_verifier, kdf_version, encrypted_user_key, vault_protection_mode, device_key_version, device_key_enabled_at, device_key_backup_acknowledged_at')
    .eq('user_id', userId)
    .maybeSingle() as { data: Record<string, unknown> | null; error: unknown };

  if (error) {
    return {
      credentials: null,
      setupRequired: false,
      setupCheckFailed: true,
    };
  }

  if (!profile?.encryption_salt) {
    return {
      credentials: null,
      setupRequired: true,
      setupCheckFailed: false,
    };
  }

  const vaultProtectionMode = normalizeVaultProtectionMode(profile.vault_protection_mode);

  return {
    credentials: {
      salt: profile.encryption_salt as string,
      verificationHash: (profile.master_password_verifier as string) || null,
      kdfVersion: (profile.kdf_version as number) ?? 1,
      encryptedUserKey: (profile.encrypted_user_key as string) || null,
      vaultProtectionMode,
    },
    setupRequired: false,
    setupCheckFailed: false,
  };
}
