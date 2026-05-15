import { useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';
import {
  generateSharedKey,
  getDecryptedPqPrivateKey,
  getDecryptedRsaPrivateKey,
} from '@/services/cryptoService';
import {
  ensureHybridKeyMaterial,
  KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED,
} from '@/services/keyMaterialService';
import { hybridUnwrapKey, hybridWrapKey, isHybridEncrypted } from '@/services/pqCryptoService';
import { decodeBase64Url } from '@/services/vaultOpLog/canonicalJson';
import { loadVerifiedVaultOpLogDeviceContext } from '@/services/vaultOpLog/vaultOpLogDeviceIdentityRecovery';
import { loadVaultOpLogDeviceSigningKey } from '@/services/vaultOpLog/vaultOpLogDeviceSigningKeyStore';
import type { SupabaseRpcClient } from '@/services/vaultOpLog/vaultOpLogRepository';
import { ensureInitialVaultOpLogTrust } from '@/services/vaultOpLog/vaultOpLogInitialTrustService';
import {
  getCollectionKeyEnvelope,
} from '@/services/collectionOpLog/repository';
import {
  getVerifiedCollectionBase,
  reloadAndVerifyCollection,
  submitAndVerifyCollectionMutation,
  type CollectionOpLogCrudDependencies,
} from '@/services/collectionOpLog/collectionOpLogCrudService';
import type { LocalCollectionState } from '@/services/collectionOpLog/stateMachine';
import type { VaultProviderState } from './useVaultProviderState';

const SHARING_KEY_WRAP_AAD_DOMAIN = 'singra-vault-sharing-key-wrap';
const SHARING_KEY_WRAP_AAD_VERSION = 1;

export interface SharedCollectionSummary {
  readonly id: string;
  readonly ownerId: string;
  readonly name: string;
  readonly description: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface CreateSharedCollectionInput {
  readonly name: string;
  readonly description: string | null;
  readonly masterPassword?: string;
}

export interface CollectionOpLogActions {
  readonly listSharedCollections: () => Promise<{ error: Error | null; collections: SharedCollectionSummary[] }>;
  readonly createSharedCollection: (
    input: CreateSharedCollectionInput,
  ) => Promise<{ error: Error | null; collectionId: string | null }>;
  readonly deleteSharedCollection: (collectionId: string) => Promise<{ error: Error | null }>;
}

interface CollectionMembershipRow {
  readonly collection_id: string;
}

interface CollectionMembershipReadClient {
  readonly from: (table: 'collection_op_log_members') => {
    readonly select: (columns: string) => {
      readonly eq: (
        column: 'user_id',
        value: string,
      ) => {
        readonly eq: (
          column: 'status',
          value: string,
        ) => Promise<{ readonly data: CollectionMembershipRow[] | null; readonly error: Error | null }>;
      };
    };
  };
}

interface UserPrivateMaterial {
  readonly rsaPublicKey: string;
  readonly rsaPrivateKey: string;
  readonly pqPublicKey: string;
  readonly pqSecretKey: string;
}

interface CollectionRuntimeBase {
  readonly userId: string;
  readonly vaultId: string;
  readonly authorDeviceId: string;
  readonly deviceSigningKey: CryptoKey;
  readonly trustEpoch: number;
  readonly keyMaterial: UserPrivateMaterial;
}

export function useCollectionOpLogActions(
  state: VaultProviderState,
  user: { readonly id: string } | null,
): CollectionOpLogActions {
  const loadRuntimeBase = useCallback(async (
    masterPassword?: string,
  ): Promise<CollectionRuntimeBase> => {
    if (!user) {
      throw new Error('Keine aktive Sitzung.');
    }
    if (!state.encryptionKey) {
      throw new Error('Der Tresor muss entsperrt sein.');
    }

    const vaultId = state.vaultMigrationKeyContext?.vaultId ?? await loadDefaultVaultId(user.id);
    if (!vaultId) {
      throw new Error('Vault-ID konnte nicht verifiziert geladen werden.');
    }

    let deviceContext = await loadVerifiedVaultOpLogDeviceContext({
      userId: user.id,
      vaultId,
      trustClient: supabase,
    });
    if (!deviceContext) {
      const bootstrapResult = await ensureInitialVaultOpLogTrust({
        userId: user.id,
        vaultId,
        rpcClient: supabase as unknown as SupabaseRpcClient,
      });
      if (bootstrapResult.kind === 'bootstrapped') {
        deviceContext = await loadVerifiedVaultOpLogDeviceContext({
          userId: user.id,
          vaultId,
          trustClient: supabase,
        });
      }
    }
    const identity = deviceContext?.identity ?? null;
    if (!identity) {
      throw new Error('OpLog-Device-Identitaet fehlt oder ist auf diesem Geraet nicht verfuegbar.');
    }

    const deviceSigningKey = await loadVaultOpLogDeviceSigningKey({
      userId: user.id,
      vaultId,
      deviceId: identity.deviceId,
    });
    if (!deviceSigningKey) {
      throw new Error('Device-Signing-Key fehlt.');
    }

    return {
      userId: user.id,
      vaultId,
      authorDeviceId: identity.deviceId,
      deviceSigningKey,
      trustEpoch: deviceContext.trustEpoch,
      keyMaterial: await loadUserPrivateMaterial(user.id, state.encryptionKey, masterPassword),
    };
  }, [state.encryptionKey, state.vaultMigrationKeyContext?.vaultId, user]);

  const makeDeps = useCallback((
    base: CollectionRuntimeBase,
    collectionId: string,
    collectionKey: Uint8Array,
  ): CollectionOpLogCrudDependencies => ({
    collectionId,
    actorUserId: base.userId,
    actorVaultId: base.vaultId,
    authorDeviceId: base.authorDeviceId,
    deviceSigningKey: base.deviceSigningKey,
    collectionKey,
    trustEpoch: base.trustEpoch,
    keyVersion: 1,
    rpcClient: supabase as unknown as SupabaseRpcClient,
  }), []);

  const listSharedCollections = useCallback(async () => {
    try {
      if (!user) {
        throw new Error('Keine aktive Sitzung.');
      }

      const memberships = await loadActiveCollectionMemberships(user.id);
      if (memberships.length === 0) {
        return { error: null, collections: [] };
      }

      const base = await loadRuntimeBase();
      const collections: SharedCollectionSummary[] = [];

      for (const membership of memberships) {
        const collectionKey = await loadCollectionKeyForCurrentUser(membership.collection_id, base.keyMaterial);
        if (!collectionKey) {
          continue;
        }

        try {
          const stateForCollection = await reloadAndVerifyCollection(
            makeDeps(base, membership.collection_id, collectionKey),
          );
          const metadata = readVerifiedCollectionMetadata(stateForCollection);
          if (metadata) {
            collections.push(metadata);
          }
        } finally {
          collectionKey.fill(0);
        }
      }

      collections.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
      return { error: null, collections };
    } catch (error) {
      return { error: error instanceof Error ? error : new Error('Shared Collections konnten nicht geladen werden.'), collections: [] };
    }
  }, [loadRuntimeBase, makeDeps, user]);

  const createSharedCollection = useCallback(async (input: CreateSharedCollectionInput) => {
    const collectionId = crypto.randomUUID();
    const recordId = crypto.randomUUID();
    let collectionKey: Uint8Array | null = null;
    try {
      const base = await loadRuntimeBase(input.masterPassword);
      const sharedKeyJwk = await generateSharedKey();
      collectionKey = sharedKeyJwkToBytes(sharedKeyJwk);
      const wrappedKey = await hybridWrapKey(
        sharedKeyJwk,
        base.keyMaterial.pqPublicKey,
        base.keyMaterial.rsaPublicKey,
        buildSharingKeyWrapAad({ collectionId, recipientUserId: base.userId }),
      );
      const now = new Date().toISOString();

      await submitAndVerifyCollectionMutation(
        makeDeps(base, collectionId, collectionKey),
        {
          opType: 'create',
          recordId,
          recordType: 'collection_metadata',
          plaintext: {
            schema: 'shared-collection-metadata-v1',
            id: collectionId,
            ownerId: base.userId,
            name: input.name.trim(),
            description: input.description,
            createdAt: now,
            updatedAt: now,
          },
          base: null,
          keyEnvelope: {
            recipientUserId: base.userId,
            keyVersion: 1,
            wrappedKey,
            pqWrappedKey: wrappedKey,
          },
        },
      );

      return { error: null, collectionId };
    } catch (error) {
      return {
        error: error instanceof Error ? error : new Error('Shared Collection konnte nicht erstellt werden.'),
        collectionId: null,
      };
    } finally {
      collectionKey?.fill(0);
    }
  }, [loadRuntimeBase, makeDeps]);

  const deleteSharedCollection = useCallback(async (collectionId: string) => {
    let collectionKey: Uint8Array | null = null;
    try {
      const base = await loadRuntimeBase();
      collectionKey = await loadCollectionKeyForCurrentUser(collectionId, base.keyMaterial);
      if (!collectionKey) {
        throw new Error('Collection-Key ist fuer dieses Geraet nicht verfuegbar.');
      }

      const deps = makeDeps(base, collectionId, collectionKey);
      const verifiedState = await reloadAndVerifyCollection(deps);
      const metadataRecord = findVerifiedMetadataRecord(verifiedState);
      if (!metadataRecord) {
        throw new Error('Verifizierte Collection-Metadaten fehlen.');
      }
      const baseMetadata = await getVerifiedCollectionBase(deps, verifiedState, metadataRecord.record.recordId);

      await submitAndVerifyCollectionMutation(deps, {
        opType: 'delete',
        recordId: metadataRecord.record.recordId,
        recordType: 'collection_metadata',
        plaintext: { tombstone: true },
        base: baseMetadata,
      });

      return { error: null };
    } catch (error) {
      return { error: error instanceof Error ? error : new Error('Shared Collection konnte nicht geloescht werden.') };
    } finally {
      collectionKey?.fill(0);
    }
  }, [loadRuntimeBase, makeDeps]);

  return {
    listSharedCollections,
    createSharedCollection,
    deleteSharedCollection,
  };
}

async function loadDefaultVaultId(userId: string): Promise<string | null> {
  const { data, error } = await supabase
    .from('vaults')
    .select('id')
    .eq('user_id', userId)
    .eq('is_default', true)
    .maybeSingle();

  if (error || typeof data?.id !== 'string') {
    return null;
  }

  return data.id;
}

async function loadUserPrivateMaterial(
  userId: string,
  userKey: CryptoKey,
  masterPassword?: string,
): Promise<UserPrivateMaterial> {
  await ensureHybridKeyMaterial({ userId, masterPassword, userKey });

  const { data: rsaRow, error: rsaError } = await supabase
    .from('user_keys')
    .select('public_key, encrypted_private_key')
    .eq('user_id', userId)
    .maybeSingle();
  if (rsaError || !rsaRow?.public_key || !rsaRow?.encrypted_private_key) {
    throw rsaError ?? new Error('RSA-Key-Material fehlt.');
  }

  const { data: pqRow, error: pqError } = await supabase
    .from('profiles')
    .select('pq_public_key, pq_encrypted_private_key')
    .eq('user_id', userId)
    .maybeSingle();
  if (pqError || !pqRow?.pq_public_key || !pqRow?.pq_encrypted_private_key) {
    throw pqError ?? new Error('PQ-Key-Material fehlt.');
  }

  if (!masterPassword && (!rsaRow.encrypted_private_key.startsWith('usk-v1:') || !pqRow.pq_encrypted_private_key.startsWith('usk-v1:'))) {
    throw createMasterPasswordRequiredError();
  }

  return {
    rsaPublicKey: rsaRow.public_key,
    rsaPrivateKey: await getDecryptedRsaPrivateKey(rsaRow.encrypted_private_key, userKey, masterPassword ?? ''),
    pqPublicKey: pqRow.pq_public_key,
    pqSecretKey: await getDecryptedPqPrivateKey(pqRow.pq_encrypted_private_key, userKey, masterPassword ?? ''),
  };
}

async function loadActiveCollectionMemberships(userId: string): Promise<CollectionMembershipRow[]> {
  const client = supabase as unknown as CollectionMembershipReadClient;
  const result = await client
    .from('collection_op_log_members')
    .select('collection_id')
    .eq('user_id', userId)
    .eq('status', 'active');
  if (result.error) {
    throw result.error;
  }
  return result.data ?? [];
}

async function loadCollectionKeyForCurrentUser(
  collectionId: string,
  keyMaterial: UserPrivateMaterial,
): Promise<Uint8Array | null> {
  const envelope = await getCollectionKeyEnvelope(supabase as unknown as SupabaseRpcClient, collectionId);
  if (!envelope || !isHybridEncrypted(envelope.pqWrappedKey)) {
    return null;
  }

  const sharedKeyJwk = await hybridUnwrapKey(
    envelope.pqWrappedKey,
    keyMaterial.pqSecretKey,
    keyMaterial.rsaPrivateKey,
    buildSharingKeyWrapAad({ collectionId, recipientUserId: envelope.userId }),
  );
  return sharedKeyJwkToBytes(sharedKeyJwk);
}

function buildSharingKeyWrapAad(context: { readonly collectionId: string; readonly recipientUserId: string }): string {
  return JSON.stringify({
    domain: SHARING_KEY_WRAP_AAD_DOMAIN,
    version: SHARING_KEY_WRAP_AAD_VERSION,
    envelope: 'shared-collection-key',
    collectionId: requireNonEmpty(context.collectionId, 'collectionId'),
    recipientUserId: requireNonEmpty(context.recipientUserId, 'recipientUserId'),
  });
}

function requireNonEmpty(value: string, fieldName: string): string {
  if (value.trim().length === 0) {
    throw new Error(`Sharing key wrap AAD requires ${fieldName}`);
  }
  return value;
}

function sharedKeyJwkToBytes(sharedKeyJwk: string): Uint8Array {
  const parsed = JSON.parse(sharedKeyJwk) as { readonly k?: unknown; readonly kty?: unknown };
  if (parsed.kty !== 'oct' || typeof parsed.k !== 'string') {
    throw new Error('Collection-Key JWK ist ungueltig.');
  }
  const keyBytes = decodeBase64Url(parsed.k);
  if (keyBytes.length !== 32) {
    throw new Error('Collection-Key muss 256 Bit lang sein.');
  }
  return keyBytes;
}

function readVerifiedCollectionMetadata(state: LocalCollectionState): SharedCollectionSummary | null {
  const record = findVerifiedMetadataRecord(state);
  if (!record?.plaintext) {
    return null;
  }

  const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as Record<string, unknown>;
  if (
    parsed.schema !== 'shared-collection-metadata-v1'
    || typeof parsed.id !== 'string'
    || typeof parsed.ownerId !== 'string'
    || typeof parsed.name !== 'string'
    || typeof parsed.createdAt !== 'string'
    || typeof parsed.updatedAt !== 'string'
    || (parsed.description !== null && typeof parsed.description !== 'string')
  ) {
    return null;
  }

  return {
    id: parsed.id,
    ownerId: parsed.ownerId,
    name: parsed.name,
    description: parsed.description,
    createdAt: parsed.createdAt,
    updatedAt: parsed.updatedAt,
  };
}

function findVerifiedMetadataRecord(state: LocalCollectionState) {
  return Array.from(state.recordsById.values()).find((record) => (
    record.state === 'verified' && record.record.recordType === 'collection_metadata' && !record.record.isTombstone
  )) ?? null;
}

function createMasterPasswordRequiredError(): Error & { code: string } {
  const error = new Error('Master password is required to unlock legacy sharing key material.') as Error & { code: string };
  error.code = KEY_MATERIAL_ERROR_MASTER_PASSWORD_REQUIRED;
  return error;
}
