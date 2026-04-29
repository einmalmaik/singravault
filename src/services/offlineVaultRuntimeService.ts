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

  if (isAppOnline()) {
    try {
      const rawSnapshot = await fetchRemoteOfflineSnapshot(userId, {
        persist: input.persistRemoteSnapshot !== false,
      });

      return {
        rawSnapshot,
        integritySnapshot: buildVaultIntegritySnapshot(rawSnapshot),
        source: 'remote',
      };
    } catch (error) {
      if (!isLikelyOfflineError(error)) {
        throw error;
      }
    }
  }

  const { snapshot, source } = await loadVaultSnapshot(userId);
  return {
    rawSnapshot: snapshot,
    integritySnapshot: buildVaultIntegritySnapshot(snapshot),
    source,
  };
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

  return {
    credentials: {
      salt: profile.encryption_salt as string,
      verificationHash: (profile.master_password_verifier as string) || null,
      kdfVersion: (profile.kdf_version as number) ?? 1,
      encryptedUserKey: (profile.encrypted_user_key as string) || null,
      vaultProtectionMode: normalizeVaultProtectionMode(profile.vault_protection_mode),
    },
    setupRequired: false,
    setupCheckFailed: false,
  };
}
