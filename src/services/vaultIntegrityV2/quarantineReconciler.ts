import type {
  ActiveItemQuarantineReasonV2,
  DiagnosticOnlyReasonV2,
  IntegrityDiagnostic,
  QuarantinedItemDecisionV2,
} from './types';

export type ReconciledQuarantineBucket =
  | 'active_quarantine'
  | 'orphan_remote'
  | 'missing_remote_recoverable'
  | 'missing_remote_unrecoverable'
  | 'stale_diagnostic'
  | 'closed_resolved'
  | 'conflict';

export interface LegacyQuarantineRecordLike {
  itemId?: string;
  id?: string;
  reason: string;
  observedEnvelopeHash?: string;
  manifestRevision?: number;
  hasTrustedLocalCopy?: boolean;
  resolved?: boolean;
}

export interface ReconciledQuarantineRecordV2 {
  identity: string;
  itemId: string;
  reason: ActiveItemQuarantineReasonV2 | DiagnosticOnlyReasonV2 | string;
  bucket: ReconciledQuarantineBucket;
  canRestore: boolean;
}

const ACTIVE_REASONS = new Set<string>([
  'ciphertext_changed',
  'aead_auth_failed',
  'item_envelope_malformed',
  'item_aad_mismatch',
  'item_manifest_hash_mismatch',
  'item_revision_replay',
  'item_key_id_mismatch',
  'duplicate_active_item_record',
]);

export function reconcileQuarantineRecordsV2(input: {
  activeDecisions?: QuarantinedItemDecisionV2[];
  legacyRecords?: LegacyQuarantineRecordLike[];
  diagnostics?: IntegrityDiagnostic[];
  manifestRevision?: number;
}): ReconciledQuarantineRecordV2[] {
  const records = new Map<string, ReconciledQuarantineRecordV2>();
  const manifestRevision = input.manifestRevision ?? 0;

  for (const decision of input.activeDecisions ?? []) {
    const identity = buildQuarantineIdentity({
      itemId: decision.itemId,
      reason: decision.reason,
      observedEnvelopeHash: decision.observedEnvelopeHash,
      manifestRevision: decision.manifestRevision,
    });
    records.set(identity, {
      identity,
      itemId: decision.itemId,
      reason: decision.reason,
      bucket: 'active_quarantine',
      canRestore: decision.recoverable,
    });
  }

  for (const record of input.legacyRecords ?? []) {
    const itemId = record.itemId ?? record.id;
    if (!itemId) {
      continue;
    }

    const bucket = classifyLegacyRecordBucket(record);
    const identity = buildQuarantineIdentity({
      itemId,
      reason: record.reason,
      observedEnvelopeHash: record.observedEnvelopeHash,
      manifestRevision: record.manifestRevision ?? manifestRevision,
    });
    if (records.has(identity) && bucket !== 'active_quarantine') {
      continue;
    }
    records.set(identity, {
      identity,
      itemId,
      reason: record.reason,
      bucket,
      canRestore: bucket === 'active_quarantine' && Boolean(record.hasTrustedLocalCopy),
    });
  }

  for (const diagnostic of input.diagnostics ?? []) {
    if (!diagnostic.itemId) {
      continue;
    }
    const identity = buildQuarantineIdentity({
      itemId: diagnostic.itemId,
      reason: diagnostic.code,
      observedEnvelopeHash: diagnostic.observedHashPrefix,
      manifestRevision: diagnostic.manifestRevision ?? manifestRevision,
    });
    if (records.has(identity)) {
      continue;
    }
    records.set(identity, {
      identity,
      itemId: diagnostic.itemId,
      reason: diagnostic.code,
      bucket: classifyDiagnosticBucket(diagnostic),
      canRestore: false,
    });
  }

  return [...records.values()].sort((left, right) => {
    return left.bucket.localeCompare(right.bucket)
      || left.itemId.localeCompare(right.itemId)
      || left.reason.localeCompare(right.reason);
  });
}

export function buildQuarantineIdentity(input: {
  itemId: string;
  reason: string;
  observedEnvelopeHash?: string;
  manifestRevision?: number;
}): string {
  return [
    input.itemId,
    input.reason,
    input.observedEnvelopeHash ?? '',
    input.manifestRevision ?? 0,
  ].join(':');
}

function classifyLegacyRecordBucket(record: LegacyQuarantineRecordLike): ReconciledQuarantineBucket {
  if (record.resolved) {
    return 'closed_resolved';
  }

  if (ACTIVE_REASONS.has(record.reason)) {
    return 'active_quarantine';
  }

  if (record.reason === 'unknown_on_server' || record.reason === 'orphan_remote') {
    return 'orphan_remote';
  }

  if (record.reason === 'missing_on_server') {
    return record.hasTrustedLocalCopy ? 'missing_remote_recoverable' : 'missing_remote_unrecoverable';
  }

  if (record.reason === 'duplicate_active_item_record') {
    return 'conflict';
  }

  return 'stale_diagnostic';
}

function classifyDiagnosticBucket(diagnostic: IntegrityDiagnostic): ReconciledQuarantineBucket {
  if (ACTIVE_REASONS.has(diagnostic.code)) {
    return 'active_quarantine';
  }

  if (diagnostic.code === 'orphan_remote' || diagnostic.code === 'unknown_on_server') {
    return 'orphan_remote';
  }

  if (diagnostic.code === 'missing_on_server') {
    return 'missing_remote_unrecoverable';
  }

  if (diagnostic.code === 'conflict_detected') {
    return 'conflict';
  }

  return 'stale_diagnostic';
}
