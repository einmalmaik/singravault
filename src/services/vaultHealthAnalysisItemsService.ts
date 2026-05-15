import type { VaultItemData } from '@/services/cryptoService';
import {
  loadVaultSnapshot,
  type OfflineVaultSnapshot,
} from '@/services/offlineVaultService';
import {
  checkPasswordPwned,
  checkPasswordStrength,
  type PwnedResult,
  type StrengthResult,
} from '@/services/passwordStrengthService';
import type { VaultIntegrityVerificationResult } from '@/services/vaultIntegrityService';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';
import type { VaultHealthAnalysisItem, VaultHealthSidebarSummaryInput } from '@/extensions/types';
import type { LocalVaultState, LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import type { VaultMigrationRolloutStatus } from '@/services/vaultOpLog/vaultMigrationRolloutService';

type DecryptVaultItem = (encryptedData: string, entryId: string) => Promise<VaultItemData>;
type VerifyVaultSnapshot = (
  snapshot?: OfflineVaultSnapshot,
  options?: { source?: 'remote' | 'cache' | 'empty' },
) => Promise<VaultIntegrityVerificationResult | null>;

export interface LoadVaultHealthAnalysisItemsInput {
  userId: string;
  vaultMigrationStatus: VaultMigrationRolloutStatus | null;
  opLogLocalVaultState: LocalVaultState | null;
  decryptItem: DecryptVaultItem;
  verifyIntegrity: VerifyVaultSnapshot;
}

function isPasswordItemType(value: unknown): value is 'password' {
  return value === undefined || value === null || value === 'password';
}

function isOldPassword(updatedAt: string): boolean {
  const ageMs = Date.now() - new Date(updatedAt).getTime();
  return ageMs / (1000 * 60 * 60 * 24) > 90;
}

function getHostname(url: string | undefined): string | null {
  if (!url) {
    return null;
  }

  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function buildPasswordStrengthContext(item: VaultHealthAnalysisItem): string[] {
  const hostname = getHostname(item.websiteUrl);
  return [item.title, item.username, hostname].filter((value): value is string => (
    typeof value === 'string' && value.trim().length > 0
  ));
}

interface PasswordHealthCheck {
  item: VaultHealthAnalysisItem;
  strength: StrengthResult;
  pwned: PwnedResult;
}

async function analyzePasswordHealthChecks(
  items: VaultHealthAnalysisItem[],
): Promise<PasswordHealthCheck[]> {
  const pwnedChecksBySecret = new Map<string, Promise<PwnedResult>>();

  try {
    return await Promise.all(items.map(async (item) => {
      let pwnedCheck = pwnedChecksBySecret.get(item.password);
      if (!pwnedCheck) {
        pwnedCheck = checkPasswordPwned(item.password);
        pwnedChecksBySecret.set(item.password, pwnedCheck);
      }

      const [strength, pwned] = await Promise.all([
        checkPasswordStrength(item.password, { userInputs: buildPasswordStrengthContext(item) }),
        pwnedCheck,
      ]);

      return { item, strength, pwned };
    }));
  } finally {
    pwnedChecksBySecret.clear();
  }
}

function parseVerifiedRecordPlaintext(record: LocalVerifiedRecord): Record<string, unknown> | null {
  if (
    (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
    || record.record.recordType !== 'item'
    || !record.plaintext
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

export function getVaultHealthAnalysisItemsFromOpLog(
  state: LocalVaultState | null,
): VaultHealthAnalysisItem[] {
  if (!state) {
    return [];
  }

  return Array.from(state.recordsById.values()).flatMap((record) => {
    const plaintext = parseVerifiedRecordPlaintext(record);
    if (!plaintext || !isPasswordItemType(plaintext.itemType) || typeof plaintext.password !== 'string' || !plaintext.password) {
      return [];
    }

    return [{
      id: record.record.recordId,
      title: typeof plaintext.title === 'string' ? plaintext.title : 'Unnamed',
      password: plaintext.password,
      itemType: 'password' as const,
      username: typeof plaintext.username === 'string' ? plaintext.username : undefined,
      websiteUrl: typeof plaintext.websiteUrl === 'string' ? plaintext.websiteUrl : undefined,
      updatedAt: record.record.updatedAt,
    }];
  });
}

export async function buildVaultHealthSidebarSummaryInput(
  items: VaultHealthAnalysisItem[],
): Promise<VaultHealthSidebarSummaryInput> {
  const passwordItems = items.filter((item) => item.itemType !== 'totp' && Boolean(item.password));
  const affectedItemIds = new Set<string>();
  const criticalItemIds = new Set<string>();
  const warningItemIds = new Set<string>();
  const passwordIdsBySecret = new Map<string, string[]>();
  const passwordDomainsBySecret = new Map<string, Set<string>>();
  let weak = 0;
  let pwned = 0;
  let duplicate = 0;
  let old = 0;
  let reused = 0;
  let strong = 0;
  const checkedItems = await analyzePasswordHealthChecks(passwordItems);

  for (const { item, strength, pwned: pwnedResult } of checkedItems) {
    if (strength.score <= 2) {
      weak += 1;
      affectedItemIds.add(item.id);
      (strength.score <= 1 ? criticalItemIds : warningItemIds).add(item.id);
    }

    if (pwnedResult.isPwned) {
      pwned += 1;
      affectedItemIds.add(item.id);
      criticalItemIds.add(item.id);
    }

    if (strength.score >= 3 && !pwnedResult.isPwned) {
      strong += 1;
    }

    if (isOldPassword(item.updatedAt)) {
      old += 1;
      affectedItemIds.add(item.id);
    }

    passwordIdsBySecret.set(item.password, [
      ...(passwordIdsBySecret.get(item.password) ?? []),
      item.id,
    ]);

    const domain = getHostname(item.websiteUrl);
    if (domain) {
      const domains = passwordDomainsBySecret.get(item.password) ?? new Set<string>();
      domains.add(domain);
      passwordDomainsBySecret.set(item.password, domains);
    }
  }

  for (const ids of passwordIdsBySecret.values()) {
    if (ids.length >= 2) {
      for (const id of ids) {
        duplicate += 1;
        affectedItemIds.add(id);
        warningItemIds.add(id);
      }
    }
  }

  for (const domains of passwordDomainsBySecret.values()) {
    if (domains.size >= 2) {
      reused += domains.size;
    }
  }

  const totalPasswords = passwordItems.length;
  const score = totalPasswords === 0
    ? 100
    : Math.max(0, Math.round(
      100
      - (weak / totalPasswords) * 40
      - (pwned / totalPasswords) * 40
      - (duplicate / totalPasswords) * 30
      - (old / totalPasswords) * 15
      - Math.min((reused / totalPasswords) * 15, 15),
    ));

  passwordIdsBySecret.clear();
  passwordDomainsBySecret.clear();

  return {
    score,
    passwordItems: totalPasswords,
    affectedItems: affectedItemIds.size,
    criticalItems: criticalItemIds.size,
    warningItems: warningItemIds.size,
    stats: {
      weak,
      pwned,
      duplicate,
      old,
      reused,
      strong,
    },
  };
}

export async function getVaultHealthAnalysisItemsFromLegacySnapshot(
  snapshot: OfflineVaultSnapshot,
  integrityResult: VaultIntegrityVerificationResult | null,
  decryptItem: DecryptVaultItem,
): Promise<VaultHealthAnalysisItem[]> {
  const items: VaultHealthAnalysisItem[] = [];

  for (const item of snapshot.items) {
    try {
      assertItemDecryptable({
        mode: integrityResult?.mode ?? 'integrity_unknown',
        quarantinedItems: integrityResult?.quarantinedItems ?? [],
        itemId: item.id,
      });

      const decrypted = await decryptItem(item.encrypted_data, item.id);
      const resolvedItemType = decrypted.itemType || item.item_type || 'password';
      if (resolvedItemType !== 'password' || !decrypted.password) {
        continue;
      }

      items.push({
        id: item.id,
        title: decrypted.title || 'Unnamed',
        password: decrypted.password,
        itemType: 'password',
        username: decrypted.username,
        websiteUrl: decrypted.websiteUrl || item.website_url || undefined,
        updatedAt: item.updated_at,
      });
    } catch {
      continue;
    }
  }

  return items;
}

export async function loadVaultHealthAnalysisItems(
  input: LoadVaultHealthAnalysisItemsInput,
): Promise<VaultHealthAnalysisItem[]> {
  if (input.vaultMigrationStatus === 'verified') {
    return getVaultHealthAnalysisItemsFromOpLog(input.opLogLocalVaultState);
  }

  const { snapshot, source } = await loadVaultSnapshot(input.userId);
  const integrityResult = await input.verifyIntegrity(snapshot, { source });
  return getVaultHealthAnalysisItemsFromLegacySnapshot(snapshot, integrityResult, input.decryptItem);
}
