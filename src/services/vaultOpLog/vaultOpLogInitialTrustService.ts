// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * Initial OpLog trust bootstrap for newly created vaults.
 *
 * This is only for the first local device of an empty/new vault. It creates a
 * Device-Signing-Key pair and bootstraps the remote trust/head rows through the
 * dedicated RPC. It does not use the Device Key as trust material.
 */

import { generateDeviceSigningKeyPair } from './operationSigningService';
import { computeVaultHead, sha256Base64Url } from './recordHashes';
import {
  bootstrapVaultTrust,
  getVaultHead,
  type SupabaseRpcClient,
} from './vaultOpLogRepository';
import {
  loadVaultOpLogDeviceSigningKey,
  saveVaultOpLogDeviceSigningKey,
} from './vaultOpLogDeviceSigningKeyStore';
import {
  loadVaultOpLogDeviceIdentity,
  saveVaultOpLogDeviceIdentity,
  type VaultOpLogDeviceIdentity,
} from './vaultOpLogDeviceStore';

export type EnsureInitialVaultOpLogTrustResult =
  | { readonly kind: 'bootstrapped'; readonly identity: VaultOpLogDeviceIdentity }
  | { readonly kind: 'alreadyInitialized' };

export async function ensureInitialVaultOpLogTrust(input: {
  readonly userId: string;
  readonly vaultId: string;
  readonly rpcClient: SupabaseRpcClient;
}): Promise<EnsureInitialVaultOpLogTrustResult> {
  const existingHead = await getVaultHead(input.rpcClient, input.vaultId);
  if (existingHead.kind === 'success') {
    return { kind: 'alreadyInitialized' };
  }
  if (existingHead.kind !== 'notFound') {
    throw new Error(`OpLog-Trust-Bootstrap konnte den aktuellen Vault-Head nicht sicher prüfen: ${existingHead.kind}`);
  }

  const signingContext = await getOrCreateLocalSigningContext(input.userId, input.vaultId);
  await saveVaultOpLogDeviceSigningKey({
    userId: input.userId,
    vaultId: input.vaultId,
    deviceId: signingContext.identity.deviceId,
    privateKey: signingContext.privateKey,
  });
  saveVaultOpLogDeviceIdentity(signingContext.identity);

  const initialHead = await buildInitialVaultHead(input.vaultId);
  const initialOpId = crypto.randomUUID();
  const bootstrap = await bootstrapVaultTrust(
    input.rpcClient,
    input.vaultId,
    signingContext.identity.deviceId,
    signingContext.identity.publicSigningKeyB64Url,
    '',
    initialHead,
    initialOpId,
  );

  if (bootstrap.kind !== 'bootstrapped') {
    if (bootstrap.kind === 'trustListAlreadyExists' || bootstrap.kind === 'headAlreadyExists') {
      return { kind: 'alreadyInitialized' };
    }
    throw new Error(`OpLog-Trust-Bootstrap fehlgeschlagen: ${bootstrap.kind}`);
  }

  return { kind: 'bootstrapped', identity: signingContext.identity };
}

async function getOrCreateLocalSigningContext(
  userId: string,
  vaultId: string,
): Promise<{ readonly identity: VaultOpLogDeviceIdentity; readonly privateKey: CryptoKey }> {
  const existingIdentity = loadVaultOpLogDeviceIdentity();
  if (existingIdentity) {
    const existingKey = await loadVaultOpLogDeviceSigningKey({
      userId,
      vaultId,
      deviceId: existingIdentity.deviceId,
    });
    if (existingKey) {
      return { identity: existingIdentity, privateKey: existingKey };
    }
  }

  const keyPair = await generateDeviceSigningKeyPair();
  return {
    identity: {
      deviceId: crypto.randomUUID(),
      publicSigningKeyB64Url: keyPair.publicKeyB64Url,
    },
    privateKey: keyPair.privateKey,
  };
}

async function buildInitialVaultHead(vaultId: string): Promise<string> {
  return computeVaultHead({
    previousVaultHead: null,
    opHash: await sha256Base64Url(new TextEncoder().encode(`initial-vault-bootstrap-${vaultId}`)),
    recordId: 'bootstrap',
    recordType: 'manifest',
    newRecordHash: null,
    opType: 'create',
  });
}
