import { supabase } from '@/integrations/supabase/client';
import {
  parseVaultManifestEnvelopeV2,
  serializeVaultManifestEnvelopeV2,
} from './manifestCrypto';
import type { VaultManifestEnvelopeV2 } from './types';

export interface StoredVaultManifestEnvelopeV2 {
  userId: string;
  vaultId: string;
  manifestRevision: number;
  manifestHash: string;
  previousManifestHash: string | null;
  keyId: string;
  envelope: VaultManifestEnvelopeV2;
}

export interface ApplyVaultMutationWithManifestV2Result {
  applied: boolean;
  revision: number | string | null;
  manifest_revision: number | string | null;
  conflict_reason: string | null;
}

interface VaultManifestRow {
  user_id: string;
  vault_id: string;
  manifest_revision: number;
  manifest_hash: string;
  previous_manifest_hash: string | null;
  key_id: string;
  manifest_envelope: string;
}

export async function loadServerManifestEnvelopeV2(input: {
  userId: string;
  vaultId: string | null | undefined;
}): Promise<StoredVaultManifestEnvelopeV2 | null> {
  if (!input.vaultId) {
    return null;
  }

  const { data, error } = await supabase
    .from('vault_integrity_manifests' as never)
    .select('user_id, vault_id, manifest_revision, manifest_hash, previous_manifest_hash, key_id, manifest_envelope')
    .eq('user_id', input.userId)
    .eq('vault_id', input.vaultId)
    .maybeSingle() as { data: VaultManifestRow | null; error: { code?: string; message?: string } | null };

  if (error) {
    if (error.code === '42P01' || /does not exist/i.test(error.message ?? '')) {
      return null;
    }
    throw error;
  }

  if (!data?.manifest_envelope) {
    return null;
  }

  const parsed = parseVaultManifestEnvelopeV2(data.manifest_envelope);
  if (!parsed.ok) {
    throw new Error('Stored Manifest V2 envelope is malformed.');
  }

  return {
    userId: data.user_id,
    vaultId: data.vault_id,
    manifestRevision: data.manifest_revision,
    manifestHash: data.manifest_hash,
    previousManifestHash: data.previous_manifest_hash,
    keyId: data.key_id,
    envelope: parsed.envelope,
  };
}

export async function persistServerManifestEnvelopeV2(input: {
  userId: string;
  vaultId: string;
  envelope: VaultManifestEnvelopeV2;
  manifestHash: string;
  previousManifestHash?: string | null;
  expectedPreviousManifestRevision?: number | null;
  expectedPreviousManifestHash?: string | null;
}): Promise<void> {
  const current = await loadServerManifestEnvelopeV2({
    userId: input.userId,
    vaultId: input.vaultId,
  });

  if (current) {
    if (input.expectedPreviousManifestRevision !== undefined
      && current.manifestRevision !== input.expectedPreviousManifestRevision) {
      throw new Error('Manifest V2 write conflict: revision changed before persist.');
    }
    if (input.expectedPreviousManifestHash !== undefined
      && current.manifestHash !== input.expectedPreviousManifestHash) {
      throw new Error('Manifest V2 write conflict: hash changed before persist.');
    }
    if (current.manifestRevision > input.envelope.manifestRevision) {
      throw new Error('Manifest V2 write rejected: server has a newer manifest revision.');
    }
    if (current.manifestRevision === input.envelope.manifestRevision
      && current.manifestHash !== input.manifestHash) {
      throw new Error('Manifest V2 write rejected: same revision has a different manifest hash.');
    }
  }

  const { error } = await supabase
    .from('vault_integrity_manifests' as never)
    .upsert({
      user_id: input.userId,
      vault_id: input.vaultId,
      manifest_revision: input.envelope.manifestRevision,
      manifest_hash: input.manifestHash,
      previous_manifest_hash: input.previousManifestHash ?? null,
      key_id: input.envelope.keyId,
      manifest_envelope: serializeVaultManifestEnvelopeV2(input.envelope),
      updated_at: new Date().toISOString(),
    } as never, { onConflict: 'vault_id' })
    .select('vault_id')
    .single();

  if (error) {
    throw error;
  }
}

export async function applyVaultMutationWithManifestV2(input: {
  baseRevision?: number | null;
  type: 'upsert_item' | 'delete_item' | 'upsert_category' | 'delete_category' | 'restore_item';
  payload: Record<string, unknown>;
  expectedManifestRevision?: number | null;
  expectedManifestHash?: string | null;
  envelope: VaultManifestEnvelopeV2;
  manifestHash: string;
  previousManifestHash?: string | null;
}): Promise<ApplyVaultMutationWithManifestV2Result> {
  const { data, error } = await supabase.rpc(
    'apply_vault_mutation_v2' as never,
    {
      p_base_revision: input.baseRevision ?? null,
      p_type: input.type,
      p_payload: input.payload,
      p_expected_manifest_revision: input.expectedManifestRevision ?? null,
      p_expected_manifest_hash: input.expectedManifestHash ?? null,
      p_manifest_revision: input.envelope.manifestRevision,
      p_manifest_hash: input.manifestHash,
      p_previous_manifest_hash: input.previousManifestHash ?? null,
      p_key_id: input.envelope.keyId,
      p_manifest_envelope: serializeVaultManifestEnvelopeV2(input.envelope),
    } as never,
  ) as unknown as {
    data: ApplyVaultMutationWithManifestV2Result | null;
    error: { message?: string } | null;
  };

  if (error) {
    throw error;
  }

  return data ?? {
    applied: false,
    revision: null,
    manifest_revision: null,
    conflict_reason: 'empty_result',
  };
}
