// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Recovers non-secret OpLog device identity metadata when localStorage lost
 * the identity but IndexedDB still contains the non-extractable signing key.
 *
 * This does not create a new device identity and never exports private key
 * material. A candidate is accepted only when a local private key can prove
 * possession against the public key of a trusted cloud device record.
 */

import {
  doesDeviceSigningKeyMatchPublicKey,
} from './operationSigningService';
import {
  loadVaultOpLogDeviceSigningKey,
  listVaultOpLogDeviceSigningKeyRefs,
} from './vaultOpLogDeviceSigningKeyStore';
import {
  loadVaultOpLogDeviceIdentity,
  saveVaultOpLogDeviceIdentity,
  type VaultOpLogDeviceIdentity,
} from './vaultOpLogDeviceStore';
import {
  loadVerifiedVaultOpLogOfflineCache,
  type VaultOpLogOfflineCacheEntry,
} from './vaultOpLogOfflineStore';

export interface VaultOpLogDeviceTrustLookupClient {
  readonly from: (table: 'vault_device_trust_records') => {
    select: (columns: string) => {
      eq: (column: string, value: string) => {
        eq: (column: string, value: string) => Promise<{
          readonly data: unknown;
          readonly error: unknown;
        }>;
      };
    };
  };
}

export interface RecoverVaultOpLogDeviceIdentityInput {
  readonly userId: string;
  readonly vaultId: string;
  readonly trustClient: VaultOpLogDeviceTrustLookupClient;
}

interface TrustedDeviceTrustRow {
  readonly deviceId: string;
  readonly publicSigningKeyB64Url: string;
  readonly trustEpoch: number;
}

export interface VerifiedVaultOpLogDeviceContext {
  readonly identity: VaultOpLogDeviceIdentity;
  readonly trustEpoch: number;
}

export async function loadVerifiedVaultOpLogDeviceContext(
  input: RecoverVaultOpLogDeviceIdentityInput,
): Promise<VerifiedVaultOpLogDeviceContext | null> {
  const identity = loadVaultOpLogDeviceIdentity()
    ?? await recoverVaultOpLogDeviceIdentity(input);
  if (!identity) {
    return null;
  }

  const trustRows = await loadTrustedDeviceRows(input.trustClient, input.vaultId);
  const trust = trustRows.find((row) =>
    row.deviceId === identity.deviceId
    && row.publicSigningKeyB64Url === identity.publicSigningKeyB64Url
  );
  if (!trust) {
    return null;
  }

  return {
    identity,
    trustEpoch: trust.trustEpoch,
  };
}

export async function recoverVaultOpLogDeviceIdentity(
  input: RecoverVaultOpLogDeviceIdentityInput,
): Promise<VaultOpLogDeviceIdentity | null> {
  return recoverDeviceIdentityFromTrustedDevices({
    userId: input.userId,
    vaultId: input.vaultId,
    trustRows: await loadTrustedDeviceRows(input.trustClient, input.vaultId),
  });
}

export async function recoverVaultOpLogDeviceIdentityFromOfflineCache(input: {
  readonly userId: string;
  readonly vaultId: string;
}): Promise<VaultOpLogDeviceIdentity | null> {
  const cache = await loadVerifiedVaultOpLogOfflineCache(input).catch(() => null);
  if (!cache) {
    return null;
  }

  return recoverDeviceIdentityFromTrustedDevices({
    userId: input.userId,
    vaultId: input.vaultId,
    trustRows: trustedDeviceRowsFromOfflineCache(cache),
  });
}

async function loadTrustedDeviceRows(
  trustClient: VaultOpLogDeviceTrustLookupClient,
  vaultId: string,
): Promise<TrustedDeviceTrustRow[]> {
  const { data, error } = await trustClient
    .from('vault_device_trust_records')
    .select('device_id,public_signing_key,trust_epoch,status')
    .eq('vault_id', vaultId)
    .eq('status', 'trusted');

  if (error || !Array.isArray(data)) {
    return [];
  }

  return data.flatMap((row) => {
    const mapped = mapTrustedDeviceTrustRow(row);
    return mapped ? [mapped] : [];
  });
}

async function recoverDeviceIdentityFromTrustedDevices(input: {
  readonly userId: string;
  readonly vaultId: string;
  readonly trustRows: readonly TrustedDeviceTrustRow[];
}): Promise<VaultOpLogDeviceIdentity | null> {
  const localRefs = await listVaultOpLogDeviceSigningKeyRefs({
    userId: input.userId,
    vaultId: input.vaultId,
  });

  if (localRefs.length === 0 || input.trustRows.length === 0) {
    return null;
  }

  const trustByDeviceId = new Map(input.trustRows.map((row) => [row.deviceId, row]));
  for (const ref of localRefs) {
    const trust = trustByDeviceId.get(ref.deviceId);
    if (!trust) {
      continue;
    }

    const privateKey = await loadVaultOpLogDeviceSigningKey(ref);
    if (!privateKey) {
      continue;
    }

    const matches = await doesDeviceSigningKeyMatchPublicKey(
      privateKey,
      trust.publicSigningKeyB64Url,
    ).catch(() => false);
    if (!matches) {
      continue;
    }

    const identity = {
      deviceId: ref.deviceId,
      publicSigningKeyB64Url: trust.publicSigningKeyB64Url,
    };
    saveVaultOpLogDeviceIdentity(identity);
    return identity;
  }

  return null;
}

function trustedDeviceRowsFromOfflineCache(
  cache: VaultOpLogOfflineCacheEntry,
): TrustedDeviceTrustRow[] {
  return cache.trustedDevices.flatMap((device) => {
    if (device.status !== 'trusted') {
      return [];
    }

    return [{
      deviceId: device.deviceId,
      publicSigningKeyB64Url: device.publicSigningKey,
      trustEpoch: device.trustEpoch,
    }];
  });
}

function mapTrustedDeviceTrustRow(row: unknown): TrustedDeviceTrustRow | null {
  if (!row || typeof row !== 'object') {
    return null;
  }
  const value = row as Record<string, unknown>;
  const deviceId = value.device_id;
  const publicSigningKey = value.public_signing_key;
  const status = value.status;
  const trustEpoch = value.trust_epoch;
  if (
    typeof deviceId !== 'string'
    || deviceId.length === 0
    || typeof publicSigningKey !== 'string'
    || publicSigningKey.length === 0
    || !Number.isSafeInteger(trustEpoch)
    || trustEpoch < 0
    || status !== 'trusted'
  ) {
    return null;
  }

  return {
    deviceId,
    publicSigningKeyB64Url: publicSigningKey,
    trustEpoch,
  };
}
