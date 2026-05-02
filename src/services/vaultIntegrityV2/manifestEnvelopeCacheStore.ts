import {
  MANIFEST_ENVELOPES_STORE,
  withIntegrityObjectStore,
} from '@/services/integrityBaselineStore';
import {
  parseVaultManifestEnvelopeV2,
  serializeVaultManifestEnvelopeV2,
} from './manifestCrypto';
import type { VaultManifestEnvelopeV2 } from './types';

export interface CachedVaultManifestEnvelopeV2 {
  userId: string;
  vaultId: string;
  manifestRevision: number;
  manifestHash: string;
  previousManifestHash: string | null;
  keyId: string;
  envelope: VaultManifestEnvelopeV2;
}

interface CachedVaultManifestEnvelopeRecordV1 {
  key: string;
  userId: string;
  vaultId: string;
  manifestRevision: number;
  manifestHash: string;
  previousManifestHash: string | null;
  keyId: string;
  manifestEnvelope: string;
  updatedAt: string;
}

function manifestCacheKey(userId: string, vaultId: string): string {
  return `${userId}:${vaultId}`;
}

export async function loadCachedManifestEnvelopeV2(input: {
  userId: string;
  vaultId: string | null | undefined;
}): Promise<CachedVaultManifestEnvelopeV2 | null> {
  if (!input.vaultId) {
    return null;
  }

  return withIntegrityObjectStore<CachedVaultManifestEnvelopeV2 | null>(
    MANIFEST_ENVELOPES_STORE,
    'readonly',
    (store, resolve, reject) => {
      const request = store.get(manifestCacheKey(input.userId, input.vaultId as string));
      request.onsuccess = () => {
        const record = request.result as CachedVaultManifestEnvelopeRecordV1 | undefined;
        if (!record?.manifestEnvelope) {
          resolve(null);
          return;
        }

        const parsed = parseVaultManifestEnvelopeV2(record.manifestEnvelope);
        if (!parsed.ok) {
          resolve(null);
          return;
        }

        resolve({
          userId: record.userId,
          vaultId: record.vaultId,
          manifestRevision: record.manifestRevision,
          manifestHash: record.manifestHash,
          previousManifestHash: record.previousManifestHash,
          keyId: record.keyId,
          envelope: parsed.envelope,
        });
      };
      request.onerror = () => reject(request.error);
    },
  );
}

export async function saveCachedManifestEnvelopeV2(input: CachedVaultManifestEnvelopeV2): Promise<void> {
  await withIntegrityObjectStore<void>(
    MANIFEST_ENVELOPES_STORE,
    'readwrite',
    (store, resolve, reject) => {
      const record: CachedVaultManifestEnvelopeRecordV1 = {
        key: manifestCacheKey(input.userId, input.vaultId),
        userId: input.userId,
        vaultId: input.vaultId,
        manifestRevision: input.manifestRevision,
        manifestHash: input.manifestHash,
        previousManifestHash: input.previousManifestHash,
        keyId: input.keyId,
        manifestEnvelope: serializeVaultManifestEnvelopeV2(input.envelope),
        updatedAt: new Date().toISOString(),
      };
      const request = store.put(record);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    },
  );
}
