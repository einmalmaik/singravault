// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Item List Component
 *
 * Displays vault items in grid or list view with filtering,
 * search, and decryption.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  ChevronDown,
  ChevronRight,
  Clock3,
  Cloud,
  Copy,
  Edit,
  Eye,
  GripVertical,
  KeyRound,
  Loader2,
  Pin,
  Plus,
  RefreshCw,
  Shield,
  ShieldCheck,
  Star,
  Trash2,
  TriangleAlert,
  X,
} from 'lucide-react';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { useVault } from '@/contexts/VaultContext';
import { useAuth } from '@/contexts/AuthContext';
import { getServiceHooks } from '@/extensions/registry';
import { cn } from '@/lib/utils';
import { ItemFilter, ViewMode } from '@/pages/VaultPage';
import { VaultItemData } from '@/services/cryptoService';
import { writeClipboard } from '@/services/clipboardService';
import { isVaultItemEnvelopeV2 } from '@/services/vaultIntegrityV2/itemEnvelopeCrypto';
import {
  isAppOnline,
  loadVaultSnapshot,
} from '@/services/offlineVaultService';
import {
  LegacyVaultMetadataMigrationPersistenceError,
  migrateLegacyVaultItemEncryptionAndMetadata,
  migrateLegacyVaultItemMetadata,
} from '@/services/legacyVaultMetadataMigrationService';
import type { QuarantinedVaultItem } from '@/services/vaultIntegrityService';
import { assertItemDecryptable } from '@/services/vaultQuarantineOrchestrator';
import { getVerifiedRecordIdsForEgress } from '@/services/vaultOpLog';
import type { ItemPlaintext } from '@/services/vaultOpLog/vaultOpLogCrudService';
import type { LocalVerifiedRecord } from '@/services/vaultOpLog/vaultStateMachine';
import { useToast } from '@/hooks/use-toast';
import { VaultItemCard } from './VaultItemCard';
import { VaultIcon } from '@/components/icons/VaultIcon';
import { VaultQuarantinedItemCard } from './VaultQuarantinedItemCard';
import { VaultItemPreviewPanel } from './VaultItemPreviewPanel';
import { VaultQuarantinePanel } from './VaultQuarantinePanel';
import {
  VaultQuarantineRestoreProgressDialog,
  type VaultQuarantineRestoreProgressStatus,
} from './VaultQuarantineRestoreProgressDialog';

const VAULT_ITEM_DRAG_MIME = 'application/x-singra-vault-item-id';
const DECRYPT_BATCH_SIZE = 25;
const QUARANTINE_SUMMARY_THRESHOLD = 2;
const CLOUD_SYNC_REFRESH_INTERVAL_MS = 60_000;
const CLOUD_SYNC_MIN_REQUEST_GAP_MS = 25_000;
const RECENT_SECTION_LIMIT = 8;
const TOUCH_DRAG_ACTIVATION_MS = 260;
const TOUCH_DRAG_MOVE_THRESHOLD_PX = 8;
const DRAG_SCROLL_EDGE_PX = 96;
const DRAG_SCROLL_STEP_PX = 28;
const FAVORITE_ACTION_COOLDOWN_MS = 3_000;
const FAVORITE_COLLAPSED_LIMIT_MOBILE = 4;
const FAVORITE_COLLAPSED_LIMIT_DESKTOP = 6;
const FOCUS_HIGHLIGHT_MS = 10_000;

interface VaultItem {
  id: string;
  vault_id: string;
  title: string;
  website_url: string | null;
  icon_url: string | null;
  item_type: 'password' | 'note' | 'totp' | 'card';
  is_favorite: boolean | null;
  category_id: string | null;
  created_at: string;
  updated_at: string;
  decryptedData?: VaultItemData;
}

interface VaultItemListProps {
  searchQuery: string;
  filter: ItemFilter;
  categoryId: string | null;
  viewMode: ViewMode;
  onEditItem: (itemId: string) => void;
  refreshKey?: number;
  securityStatusLoading?: boolean;
  focusItemId?: string | null;
}

type RenderableVaultListEntry =
  | { kind: 'item'; item: VaultItem }
  | { kind: 'quarantined'; item: VaultItem; quarantine: QuarantinedVaultItem };

interface BulkRestoreProgress {
  open: boolean;
  status: VaultQuarantineRestoreProgressStatus;
  total: number;
  completed: number;
  failed: number;
  currentItemId: string | null;
  lastError: string | null;
}

interface VaultItemListIntegrityGate {
  readonly mode?: string;
  readonly quarantinedItems: QuarantinedVaultItem[];
  readonly isFirstCheck?: boolean;
}

interface CategorySummary {
  readonly id: string;
  readonly name: string;
}

interface PointerDragState {
  readonly itemId: string;
  readonly title: string;
  readonly pointerId: number;
  readonly pointerType: string;
  readonly active: boolean;
  readonly originX: number;
  readonly originY: number;
  readonly x: number;
  readonly y: number;
  readonly dropCategoryId: string | null;
}

function canDecryptFromIntegrityResult(
  result: VaultItemListIntegrityGate | null | undefined,
  itemId: string,
): boolean {
  if (!result?.mode) {
    return false;
  }

  if (
    result.mode === 'quarantine'
    && result.quarantinedItems.some((item) => item.id === itemId)
  ) {
    return false;
  }

  try {
    assertItemDecryptable({
      mode: result.mode,
      quarantinedItems: result.quarantinedItems,
      itemId,
    });
    return true;
  } catch {
    return false;
  }
}

function parseOpLogItemPlaintext(record: LocalVerifiedRecord): VaultItemData | null {
  if (
    (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
    || record.record.recordType !== 'item'
    || !record.plaintext
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const value = parsed as Record<string, unknown>;
    const title = typeof value.title === 'string' ? value.title : '';
    const itemType = isVaultItemType(value.itemType) ? value.itemType : 'password';

    return {
      title,
      websiteUrl: typeof value.websiteUrl === 'string' ? value.websiteUrl : undefined,
      username: typeof value.username === 'string' ? value.username : undefined,
      password: typeof value.password === 'string' ? value.password : undefined,
      notes: typeof value.notes === 'string' ? value.notes : undefined,
      itemType,
      categoryId: typeof value.categoryRecordId === 'string' ? value.categoryRecordId : null,
      isFavorite: typeof value.isFavorite === 'boolean' ? value.isFavorite : false,
      totpSecret: typeof value.totpSecret === 'string' ? value.totpSecret : undefined,
      totpIssuer: typeof value.totpIssuer === 'string' ? value.totpIssuer : undefined,
      totpLabel: typeof value.totpLabel === 'string' ? value.totpLabel : undefined,
      totpAlgorithm: isTotpAlgorithm(value.totpAlgorithm) ? value.totpAlgorithm : undefined,
      totpDigits: value.totpDigits === 6 || value.totpDigits === 8 ? value.totpDigits : undefined,
      totpPeriod: typeof value.totpPeriod === 'number' ? value.totpPeriod : undefined,
      customFields: isStringRecord(value.customFields) ? value.customFields : undefined,
    };
  } catch {
    return null;
  }
}

function parseOpLogCategoryPlaintext(record: LocalVerifiedRecord): CategorySummary | null {
  if (
    (record.recordState !== 'verified' && record.recordState !== 'restoredFromSnapshot')
    || record.record.recordType !== 'category'
    || !record.plaintext
  ) {
    return null;
  }

  try {
    const parsed = JSON.parse(new TextDecoder().decode(record.plaintext)) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return null;
    }
    const value = parsed as Record<string, unknown>;
    return {
      id: record.record.recordId,
      name: typeof value.name === 'string' && value.name.trim() ? value.name : 'Kategorie',
    };
  } catch {
    return null;
  }
}

function parseVerifiedPlaintextObject(record: LocalVerifiedRecord | null | undefined): Record<string, unknown> | null {
  if (!record?.plaintext) {
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

function readOptionalSortOrder(value: unknown): number | null {
  if (value === null || value === undefined) {
    return null;
  }
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function mapOpLogRecordToVaultItem(record: LocalVerifiedRecord): VaultItem | null {
  const decryptedData = parseOpLogItemPlaintext(record);
  if (!decryptedData) {
    return null;
  }

  return {
    id: record.record.recordId,
    vault_id: record.record.vaultId,
    title: decryptedData.title ?? '',
    website_url: decryptedData.websiteUrl ?? null,
    icon_url: null,
    item_type: decryptedData.itemType ?? 'password',
    is_favorite: decryptedData.isFavorite ?? false,
    category_id: decryptedData.categoryId ?? null,
    created_at: record.record.createdAt,
    updated_at: record.record.updatedAt,
    decryptedData,
  };
}

function itemPlaintextFromVaultItem(
  item: VaultItem,
  overrides: Partial<Pick<ItemPlaintext, 'categoryRecordId' | 'isFavorite'>>,
  sourcePlaintext?: Record<string, unknown> | null,
): ItemPlaintext | null {
  const data = item.decryptedData;
  if (!data) {
    return null;
  }
  const sourceCustomFields = sourcePlaintext?.customFields;

  return {
    title: data.title ?? item.title ?? '',
    websiteUrl: data.websiteUrl ?? item.website_url ?? null,
    username: data.username ?? null,
    password: data.password ?? null,
    notes: data.notes ?? null,
    itemType: data.itemType === 'note'
      ? 'note'
      : data.itemType === 'totp'
        ? 'totp'
        : data.itemType === 'card'
          ? 'card'
          : 'password',
    categoryRecordId: overrides.categoryRecordId ?? data.categoryId ?? item.category_id ?? null,
    isFavorite: overrides.isFavorite ?? data.isFavorite ?? item.is_favorite ?? false,
    sortOrder: readOptionalSortOrder(sourcePlaintext?.sortOrder),
    totpSecret: data.totpSecret ?? null,
    totpIssuer: data.totpIssuer ?? null,
    totpLabel: data.totpLabel ?? null,
    totpAlgorithm: data.totpAlgorithm ?? null,
    totpDigits: data.totpDigits ?? null,
    totpPeriod: data.totpPeriod ?? null,
    customFields: data.customFields ?? (sourceCustomFields === null
      ? null
      : isStringRecord(sourceCustomFields)
        ? sourceCustomFields
        : null),
  };
}

function getItemTitle(item: VaultItem): string {
  return item.decryptedData?.title || item.title || 'Ohne Titel';
}

function getItemWebsiteUrl(item: VaultItem): string | null {
  return item.decryptedData?.websiteUrl || item.website_url || null;
}

function getItemUsername(item: VaultItem): string | null {
  return item.decryptedData?.username || null;
}

function getItemCategoryId(item: VaultItem): string | null {
  return item.decryptedData?.categoryId ?? item.category_id ?? null;
}

function isItemFavorite(item: VaultItem): boolean {
  return typeof item.decryptedData?.isFavorite === 'boolean'
    ? item.decryptedData.isFavorite
    : !!item.is_favorite;
}

function formatRelativeUpdatedAt(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) {
    return 'kürzlich';
  }

  const diffMs = Date.now() - timestamp;
  const minuteMs = 60_000;
  const hourMs = 60 * minuteMs;
  const dayMs = 24 * hourMs;

  if (diffMs < minuteMs) return 'gerade eben';
  if (diffMs < hourMs) {
    const minutes = Math.max(1, Math.round(diffMs / minuteMs));
    return `vor ${minutes} Min`;
  }
  if (diffMs < dayMs) {
    const hours = Math.max(1, Math.round(diffMs / hourMs));
    return `vor ${hours} Std`;
  }

  const days = Math.max(1, Math.round(diffMs / dayMs));
  return `vor ${days} Tag${days === 1 ? '' : 'en'}`;
}

function formatVaultItemMetaDate(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '—';
  }

  return new Intl.DateTimeFormat('de-DE', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function scrollViewportForDrag(clientY: number): void {
  if (typeof window === 'undefined' || !Number.isFinite(clientY)) {
    return;
  }

  const viewportHeight = window.innerHeight || 0;
  if (viewportHeight <= 0) {
    return;
  }

  if (clientY < DRAG_SCROLL_EDGE_PX) {
    window.scrollBy({ top: -DRAG_SCROLL_STEP_PX, behavior: 'auto' });
  } else if (clientY > viewportHeight - DRAG_SCROLL_EDGE_PX) {
    window.scrollBy({ top: DRAG_SCROLL_STEP_PX, behavior: 'auto' });
  }
}

function isVaultItemType(value: unknown): value is VaultItem['item_type'] {
  return value === 'password' || value === 'note' || value === 'totp' || value === 'card';
}

function isTotpAlgorithm(value: unknown): value is NonNullable<VaultItemData['totpAlgorithm']> {
  return value === 'SHA1' || value === 'SHA256' || value === 'SHA512';
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return !!value
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.values(value).every((entry) => typeof entry === 'string');
}

function getQuarantineIgnoreToken(item: QuarantinedVaultItem): string {
  return `${item.reason}:${item.updatedAt ?? ''}`;
}

async function mapInBatches<TInput, TOutput>(
  items: TInput[],
  batchSize: number,
  mapper: (item: TInput) => Promise<TOutput>,
): Promise<TOutput[]> {
  const results: TOutput[] = [];

  for (let start = 0; start < items.length; start += batchSize) {
    const batch = items.slice(start, start + batchSize);
    results.push(...await Promise.all(batch.map(mapper)));

    if (start + batchSize < items.length) {
      await new Promise<void>((resolve) => {
        globalThis.setTimeout(resolve, 0);
      });
    }
  }

  return results;
}

export function VaultItemList({
  searchQuery,
  filter,
  categoryId,
  viewMode,
  onEditItem,
  refreshKey,
  securityStatusLoading = false,
  focusItemId = null,
}: VaultItemListProps) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const {
    decryptItem,
    decryptItemForLegacyMigration,
    encryptItem,
    isDuressMode,
    lastIntegrityResult,
    opLogRestoreRecord,
    quarantineResolutionById,
    reportUnreadableItems,
    refreshIntegrityBaseline,
    verifyIntegrity,
    vaultDataVersion,
    vaultMigrationStatus,
    opLogLocalVaultState,
    opLogUpdateItem,
    opLogUiRefresh,
    opLogUiView,
    opLogDeleteItem,
  } = useVault();
  const useOpLogVerifiedRuntime = vaultMigrationStatus === 'verified';

  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const [ignoredQuarantineById, setIgnoredQuarantineById] = useState<Record<string, string>>({});
  const [showIgnoredQuarantine, setShowIgnoredQuarantine] = useState(false);
  const [bulkRestoreConfirmOpen, setBulkRestoreConfirmOpen] = useState(false);
  const [bulkRestoreProgress, setBulkRestoreProgress] = useState<BulkRestoreProgress>({
    open: false,
    status: 'running',
    total: 0,
    completed: 0,
    failed: 0,
    currentItemId: null,
    lastError: null,
  });
  const [revalidating, setRevalidating] = useState(false);
  const [backgroundSyncing, setBackgroundSyncing] = useState(false);
  const [lastCloudSyncAt, setLastCloudSyncAt] = useState<Date | null>(null);
  const [cloudSyncTick, setCloudSyncTick] = useState(0);
  const [recentlyCopiedItemIds, setRecentlyCopiedItemIds] = useState<string[]>([]);
  const [collapsedCategoryIds, setCollapsedCategoryIds] = useState<Set<string>>(() => new Set());
  const [dropTargetCategoryId, setDropTargetCategoryId] = useState<string | null>(null);
  const [pointerDrag, setPointerDrag] = useState<PointerDragState | null>(null);
  const [nativeDraggingItemId, setNativeDraggingItemId] = useState<string | null>(null);
  const [favoriteExpanded, setFavoriteExpanded] = useState(false);
  const [favoriteCollapsedLimit, setFavoriteCollapsedLimit] = useState(FAVORITE_COLLAPSED_LIMIT_DESKTOP);
  const [previewItemId, setPreviewItemId] = useState<string | null>(null);
  const [deletePreviewItemId, setDeletePreviewItemId] = useState<string | null>(null);
  const [deletingPreviewItem, setDeletingPreviewItem] = useState(false);
  const [highlightedItemId, setHighlightedItemId] = useState<string | null>(null);
  const pointerDragRef = useRef<PointerDragState | null>(null);
  const pointerDragTimerRef = useRef<number | null>(null);
  const favoriteScrollerRef = useRef<HTMLDivElement | null>(null);
  const itemElementRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const focusHighlightTimerRef = useRef<number | null>(null);
  const lastHandledFocusItemIdRef = useRef<string | null>(null);
  const favoriteScrollDragRef = useRef<{
    pointerId: number;
    startX: number;
    scrollLeft: number;
    dragging: boolean;
  } | null>(null);
  const nextFavoriteActionAtRef = useRef(0);
  const suppressedCategoryToggleRef = useRef<{ categoryId: string; until: number } | null>(null);
  const failedDecryptPayloadByItemIdRef = useRef<Map<string, string>>(new Map());
  const loggedDecryptFailuresRef = useRef<Set<string>>(new Set());
  const revalidationRequestIdRef = useRef(0);
  const revalidatingRef = useRef(false);
  const opLogCloudSyncRef = useRef(false);
  const lastCloudSyncRequestAtRef = useRef(0);
  const fetchItemsRef = useRef(false);
  const pendingFetchItemsRef = useRef(false);
  const hasRenderedVaultContentRef = useRef(false);
  const decryptItemRef = useRef(decryptItem);
  const decryptItemForLegacyMigrationRef = useRef(decryptItemForLegacyMigration);
  const encryptItemRef = useRef(encryptItem);
  const reportUnreadableItemsRef = useRef(reportUnreadableItems);
  const verifyIntegrityRef = useRef(verifyIntegrity);
  const refreshIntegrityBaselineRef = useRef(refreshIntegrityBaseline);

  useEffect(() => {
    decryptItemRef.current = decryptItem;
    decryptItemForLegacyMigrationRef.current = decryptItemForLegacyMigration;
    encryptItemRef.current = encryptItem;
    reportUnreadableItemsRef.current = reportUnreadableItems;
    verifyIntegrityRef.current = verifyIntegrity;
    refreshIntegrityBaselineRef.current = refreshIntegrityBaseline;
  }, [decryptItem, decryptItemForLegacyMigration, encryptItem, refreshIntegrityBaseline, reportUnreadableItems, verifyIntegrity]);

  useEffect(() => () => {
    if (focusHighlightTimerRef.current !== null) {
      window.clearTimeout(focusHighlightTimerRef.current);
    }
  }, []);

  useEffect(() => {
    failedDecryptPayloadByItemIdRef.current.clear();
    loggedDecryptFailuresRef.current.clear();
    hasRenderedVaultContentRef.current = false;
    setLastCloudSyncAt(null);
    setBackgroundSyncing(false);
  }, [userId, isDuressMode]);

  useEffect(() => {
    const updateFavoriteLimit = () => {
      setFavoriteCollapsedLimit(
        window.innerWidth < 768
          ? FAVORITE_COLLAPSED_LIMIT_MOBILE
          : FAVORITE_COLLAPSED_LIMIT_DESKTOP,
      );
    };

    updateFavoriteLimit();
    window.addEventListener('resize', updateFavoriteLimit);
    return () => window.removeEventListener('resize', updateFavoriteLimit);
  }, []);

  useEffect(() => {
    if (!nativeDraggingItemId) {
      return undefined;
    }

    const handleDragOver = (event: DragEvent) => {
      scrollViewportForDrag(event.clientY);
    };

    window.addEventListener('dragover', handleDragOver);
    return () => window.removeEventListener('dragover', handleDragOver);
  }, [nativeDraggingItemId]);

  useEffect(() => {
    if (!userId) {
      return undefined;
    }

    const requestCloudSync = (options?: { force?: boolean }) => {
      if (!isAppOnline()) {
        return;
      }

      const now = Date.now();
      if (!options?.force && now - lastCloudSyncRequestAtRef.current < CLOUD_SYNC_MIN_REQUEST_GAP_MS) {
        return;
      }

      lastCloudSyncRequestAtRef.current = now;
      setCloudSyncTick((tick) => tick + 1);
    };

    const requestVisibleCloudSync = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
        return;
      }

      requestCloudSync();
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        requestCloudSync();
      }
    };

    const handleOnline = () => requestCloudSync({ force: true });

    window.addEventListener('focus', requestVisibleCloudSync);
    window.addEventListener('online', handleOnline);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    const intervalId = window.setInterval(requestVisibleCloudSync, CLOUD_SYNC_REFRESH_INTERVAL_MS);

    return () => {
      window.removeEventListener('focus', requestVisibleCloudSync);
      window.removeEventListener('online', handleOnline);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      window.clearInterval(intervalId);
    };
  }, [userId]);

  const revalidateRemoteIntegrity = useCallback(async () => {
    if (!userId || revalidatingRef.current || useOpLogVerifiedRuntime) {
      return;
    }

    const requestId = revalidationRequestIdRef.current + 1;
    revalidationRequestIdRef.current = requestId;
    revalidatingRef.current = true;
    setRevalidating(true);
    try {
      await verifyIntegrityRef.current();
    } finally {
      if (revalidationRequestIdRef.current === requestId) {
        revalidatingRef.current = false;
        setRevalidating(false);
      }
    }
  }, [useOpLogVerifiedRuntime, userId]);

  useEffect(() => {
    if (!useOpLogVerifiedRuntime || !userId || cloudSyncTick === 0 || !isAppOnline()) {
      return;
    }

    if (opLogCloudSyncRef.current) {
      return;
    }

    opLogCloudSyncRef.current = true;
    setBackgroundSyncing(true);

    void opLogUiRefresh()
      .then(() => {
        setLastCloudSyncAt(new Date());
      })
      .finally(() => {
        opLogCloudSyncRef.current = false;
        setBackgroundSyncing(false);
      });
  }, [cloudSyncTick, opLogUiRefresh, useOpLogVerifiedRuntime, userId]);

  useEffect(() => {
    async function fetchItems() {
      if (!userId) return;
      if (fetchItemsRef.current) {
        pendingFetchItemsRef.current = true;
        return;
      }

      const isBackgroundSync = hasRenderedVaultContentRef.current;
      fetchItemsRef.current = true;
      if (isBackgroundSync) {
        setBackgroundSyncing(true);
      } else {
        setLoading(true);
        setDecrypting(false);
      }
      try {
        if (useOpLogVerifiedRuntime) {
          const opLogItems = opLogLocalVaultState
            ? Array.from(opLogLocalVaultState.recordsById.values())
              .map(mapOpLogRecordToVaultItem)
              .filter((item): item is VaultItem => item !== null)
              .sort((a, b) => b.updated_at.localeCompare(a.updated_at))
            : [];

reportUnreadableItemsRef.current([]);
          setItems(opLogItems);
          hasRenderedVaultContentRef.current = true;
          setLastCloudSyncAt(new Date());
          fetchItemsRef.current = false;
          setLoading(false);
          setDecrypting(false);

          if (pendingFetchItemsRef.current) {
            pendingFetchItemsRef.current = false;
            void fetchItems();
          }

          return;
        }

        const { snapshot, source } = await loadVaultSnapshot(userId);
        const integrityResult: VaultItemListIntegrityGate | null = await verifyIntegrityRef.current(snapshot, { source });
        const allowsAnyDecrypt = integrityResult?.mode === 'healthy' || integrityResult?.mode === 'quarantine';
        if (!allowsAnyDecrypt) {
          setItems([]);
        } else {
          const canPersistMigrations = !useOpLogVerifiedRuntime
            && integrityResult?.mode === 'healthy'
            && integrityResult.isFirstCheck
            && source === 'remote'
            && isAppOnline();
          const canPersistLegacyEncryptionMigration = !useOpLogVerifiedRuntime
            && source === 'remote'
            && isAppOnline()
            && (
              integrityResult?.mode === 'healthy'
              || (
                integrityResult?.mode === 'quarantine'
                && integrityResult.quarantinedItems.length > 0
                && integrityResult.quarantinedItems.every((item) => item.reason === 'decrypt_failed')
              )
            );

          const vaultItems = [...snapshot.items].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
          let integrityBaselineDirty = false;
          const trustedItemIds = new Set<string>();
          const decryptableItemIds = new Set<string>();
          const unreadableItems: QuarantinedVaultItem[] = [];

          if (vaultItems.length > 0) {
            setDecrypting(true);
          }

          const decryptedItems = await mapInBatches(
            vaultItems,
            DECRYPT_BATCH_SIZE,
            async (item) => {
              if (!canDecryptFromIntegrityResult(integrityResult, item.id)) {
                return { ...item, decryptedData: undefined };
              }

              const cachedFailedPayload = failedDecryptPayloadByItemIdRef.current.get(item.id);
              if (cachedFailedPayload === item.encrypted_data) {
                return { ...item, decryptedData: undefined };
              }

              let decryptedData: VaultItemData | null = null;
              try {
                decryptedData = await decryptItemRef.current(item.encrypted_data, item.id);
              } catch {
                if (canPersistLegacyEncryptionMigration) {
                  let legacyMigrationDecrypt: Awaited<ReturnType<typeof decryptItemForLegacyMigrationRef.current>> | null = null;
                  try {
                    legacyMigrationDecrypt = await decryptItemForLegacyMigrationRef.current(
                      item.encrypted_data,
                      item.id,
                    );
                    if (!legacyMigrationDecrypt.legacyNoAadFallbackUsed) {
                      throw new Error('No legacy encryption migration required.');
                    }
                  } catch {
                    legacyMigrationDecrypt = null;
                  }

                  if (legacyMigrationDecrypt) {
                    try {
                      const migration = await migrateLegacyVaultItemEncryptionAndMetadata({
                        userId,
                        vaultId: snapshot.vaultId,
                        item,
                        decryptedData: legacyMigrationDecrypt.data,
                        canPersistRemote: true,
                        encryptItem: encryptItemRef.current,
                      });
                      integrityBaselineDirty = true;
                      trustedItemIds.add(item.id);
                      decryptableItemIds.add(item.id);
                      failedDecryptPayloadByItemIdRef.current.delete(item.id);

                      return {
                        ...migration.item,
                        decryptedData: migration.decryptedData,
                      };
                    } catch (migrationError) {
                      if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                        console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                        decryptableItemIds.add(item.id);
                        failedDecryptPayloadByItemIdRef.current.delete(item.id);
                        return {
                          ...item,
                          decryptedData: legacyMigrationDecrypt.data,
                        };
                      }
                      throw migrationError;
                    }
                  }
                }

                failedDecryptPayloadByItemIdRef.current.set(item.id, item.encrypted_data);
                unreadableItems.push({
                  id: item.id,
                  reason: 'decrypt_failed',
                  updatedAt: item.updated_at ?? null,
                  itemType: item.item_type ?? null,
                });
                const logKey = `${item.id}:${item.updated_at}`;
                if (!loggedDecryptFailuresRef.current.has(logKey)) {
                  loggedDecryptFailuresRef.current.add(logKey);
                  console.debug(
                    isDuressMode
                      ? 'Failed to decrypt item in Duress Mode (expected for Real items):'
                      : 'Failed to decrypt item (key mismatch or corrupt):',
                    item.id,
                  );
                }

                return { ...item, decryptedData: undefined };
              }
              if (!decryptedData) {
                throw new Error('Vault item decrypt returned no data.');
              }

              decryptableItemIds.add(item.id);
              failedDecryptPayloadByItemIdRef.current.delete(item.id);

              const migration = await migrateLegacyVaultItemMetadata({
                userId,
                vaultId: snapshot.vaultId,
                item,
                decryptedData,
                canPersistRemote: canPersistMigrations,
                encryptItem: encryptItemRef.current,
              });
              if (migration.migrated) {
                integrityBaselineDirty = true;
                trustedItemIds.add(item.id);
              }

              if (canPersistLegacyEncryptionMigration && !isVaultItemEnvelopeV2(migration.item.encrypted_data)) {
                try {
                  const encryptionMigration = await migrateLegacyVaultItemEncryptionAndMetadata({
                    userId,
                    vaultId: snapshot.vaultId,
                    item: migration.item,
                    decryptedData: migration.decryptedData,
                    canPersistRemote: true,
                    encryptItem: encryptItemRef.current,
                  });
                  integrityBaselineDirty = true;
                  trustedItemIds.add(item.id);
                  decryptableItemIds.add(item.id);
                  failedDecryptPayloadByItemIdRef.current.delete(item.id);

                  return {
                    ...encryptionMigration.item,
                    decryptedData: encryptionMigration.decryptedData,
                  };
                } catch (migrationError) {
                  if (migrationError instanceof LegacyVaultMetadataMigrationPersistenceError) {
                    console.warn('Legacy vault item encryption migration could not be persisted; will retry later.', item.id);
                    return {
                      ...migration.item,
                      decryptedData: migration.decryptedData,
                    };
                  }
                  throw migrationError;
                }
              }

              return {
                ...migration.item,
                decryptedData: migration.decryptedData,
              };
            },
          );

          reportUnreadableItemsRef.current(unreadableItems);

          const canPersistTrustedFirstBaseline = integrityResult?.mode === 'healthy'
            && integrityResult.isFirstCheck
            && source === 'remote'
            && isAppOnline()
            && unreadableItems.length === 0;

          if (
            (integrityBaselineDirty && (canPersistMigrations || canPersistLegacyEncryptionMigration))
            || canPersistTrustedFirstBaseline
          ) {
            await refreshIntegrityBaselineRef.current();
          }

          setItems(decryptedItems as VaultItem[]);
          hasRenderedVaultContentRef.current = decryptedItems.length > 0
            || (integrityResult?.mode === 'quarantine' && integrityResult.quarantinedItems.length > 0);
          setLastCloudSyncAt(new Date());

          // Cached snapshots keep the vault usable offline and while local writes
          // are pending. A lightweight remote revalidation follows so DB-side
          // tampering can move items into quarantine without waiting for edit/open.
          if (!useOpLogVerifiedRuntime && source !== 'remote' && isAppOnline()) {
            void revalidateRemoteIntegrity();
          }
        }
      } catch (err) {
        console.error('Error fetching vault items:', err);
      } finally {
        fetchItemsRef.current = false;
      }

      if (pendingFetchItemsRef.current) {
        pendingFetchItemsRef.current = false;
        void fetchItems();
      } else {
        setLoading(false);
        setDecrypting(false);
        setBackgroundSyncing(false);
      }
    }

    void fetchItems();
  }, [
    refreshKey,
    cloudSyncTick,
    isDuressMode,
    revalidateRemoteIntegrity,
    opLogLocalVaultState,
    useOpLogVerifiedRuntime,
    userId,
    vaultDataVersion,
  ]);

  const quarantinedItems = useMemo(
    () => lastIntegrityResult?.quarantinedItems ?? [],
    [lastIntegrityResult],
  );
  const quarantinedItemsById = useMemo(
    () => new Map(quarantinedItems.map((item) => [item.id, item])),
    [quarantinedItems],
  );
  const hasGroupedQuarantine = quarantinedItems.length >= QUARANTINE_SUMMARY_THRESHOLD;
  const canRenderGroupedQuarantine = filter === 'all' && !categoryId && searchQuery.trim() === '';
  const quarantineIgnoreStorageKey = user?.id
    ? `singra:vault-quarantine-ignored-items:${user.id}`
    : null;
  const activeIgnoredQuarantinedItems = useMemo(
    () => quarantinedItems.filter((item) => ignoredQuarantineById[item.id] === getQuarantineIgnoreToken(item)),
    [ignoredQuarantineById, quarantinedItems],
  );
  const activeIgnoredQuarantineIds = useMemo(
    () => new Set(activeIgnoredQuarantinedItems.map((item) => item.id)),
    [activeIgnoredQuarantinedItems],
  );
  const hasIgnoredGroupedQuarantine = hasGroupedQuarantine && activeIgnoredQuarantinedItems.length > 0;

  const canRenderInlineQuarantine = useCallback((
    item: VaultItem,
    quarantine: QuarantinedVaultItem,
  ) => {
    if (quarantinedItems.length !== 1 || searchQuery.trim() !== '') {
      return false;
    }

    const quarantinedItemType = quarantine.itemType ?? item.item_type;
    if (quarantinedItemType === 'totp') {
      return false;
    }

    if (categoryId && item.category_id !== categoryId) {
      return false;
    }

    if (filter === 'passwords') {
      return quarantinedItemType === 'password';
    }
    if (filter === 'notes') {
      return quarantinedItemType === 'note';
    }
    if (filter === 'favorites') {
      return false;
    }

    return filter === 'all';
  }, [filter, categoryId, searchQuery, quarantinedItems.length]);

  useEffect(() => {
    setShowIgnoredQuarantine(false);

    if (!quarantineIgnoreStorageKey || typeof window === 'undefined') {
      setIgnoredQuarantineById({});
      return;
    }

    try {
      const parsed = JSON.parse(window.localStorage.getItem(quarantineIgnoreStorageKey) || '{}');
      setIgnoredQuarantineById(
        parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? parsed as Record<string, string>
          : {},
      );
    } catch {
      setIgnoredQuarantineById({});
    }
  }, [quarantineIgnoreStorageKey]);

  const persistIgnoredQuarantine = useCallback((nextIgnoredById: Record<string, string>) => {
    if (!quarantineIgnoreStorageKey || typeof window === 'undefined') {
      return;
    }

    window.localStorage.setItem(quarantineIgnoreStorageKey, JSON.stringify(nextIgnoredById));
    setIgnoredQuarantineById(nextIgnoredById);
  }, [quarantineIgnoreStorageKey]);

  const handleIgnoreQuarantineItem = useCallback((item: QuarantinedVaultItem) => {
    persistIgnoredQuarantine({
      ...ignoredQuarantineById,
      [item.id]: getQuarantineIgnoreToken(item),
    });
  }, [ignoredQuarantineById, persistIgnoredQuarantine]);

  // Phase 10: when OpLog UI is available, only verified items may be searched.
  // When vault security mode is lockedCritical/safeMode/safeModeRecommended,
  // getVerifiedRecordIdsForEgress returns an empty set, effectively hiding
  // all items from search results.
  const opLogVerifiedItemIds = useMemo(
    () => getVerifiedRecordIdsForEgress(opLogUiView),
    [opLogUiView],
  );

  const markItemRecentlyUsed = useCallback((itemId: string) => {
    setRecentlyCopiedItemIds((current) => [
      itemId,
      ...current.filter((id) => id !== itemId),
    ].slice(0, 20));
  }, []);

  const categorySummaries = useMemo(() => {
    if (!opLogLocalVaultState) {
      return [] as CategorySummary[];
    }

    return Array.from(opLogLocalVaultState.recordsById.values())
      .map(parseOpLogCategoryPlaintext)
      .filter((category): category is CategorySummary => !!category)
      .sort((left, right) => left.name.localeCompare(right.name, 'de'));
  }, [opLogLocalVaultState]);

  const categoryNameById = useMemo(
    () => new Map(categorySummaries.map((category) => [category.id, category.name])),
    [categorySummaries],
  );

  const moveItemToCategory = useCallback(async (itemId: string, nextCategoryId: string | null) => {
    const item = items.find((candidate) => candidate.id === itemId);
    if (!item) {
      return;
    }

    const previousCategoryId = getItemCategoryId(item);
    if (previousCategoryId === nextCategoryId) {
      return;
    }

    const sourcePlaintext = parseVerifiedPlaintextObject(opLogLocalVaultState?.recordsById.get(itemId) as LocalVerifiedRecord | undefined);
    const plaintext = itemPlaintextFromVaultItem(item, { categoryRecordId: nextCategoryId }, sourcePlaintext);
    if (!plaintext) {
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        category_id: nextCategoryId,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, categoryId: nextCategoryId }
          : currentItem.decryptedData,
      };
    }));
    markItemRecentlyUsed(item.id);

    const result = await opLogUpdateItem(item.id, plaintext);
    if (!result.error) {
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        category_id: previousCategoryId,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, categoryId: previousCategoryId }
          : currentItem.decryptedData,
      };
    }));
    toast({
      variant: 'destructive',
      title: t('common.error'),
      description: result.error.message,
    });
  }, [items, markItemRecentlyUsed, opLogLocalVaultState, opLogUpdateItem, t, toast]);

  const openItemPreview = useCallback((item: VaultItem) => {
    markItemRecentlyUsed(item.id);
    setPreviewItemId(item.id);
  }, [markItemRecentlyUsed]);

  const setItemElementRef = useCallback((itemId: string, element: HTMLDivElement | null) => {
    if (element) {
      itemElementRefs.current.set(itemId, element);
      return;
    }
    itemElementRefs.current.delete(itemId);
  }, []);

  const editItemFromPreview = useCallback((itemId: string) => {
    markItemRecentlyUsed(itemId);
    setPreviewItemId(null);
    onEditItem(itemId);
  }, [markItemRecentlyUsed, onEditItem]);

  const toggleItemFavorite = useCallback(async (item: VaultItem) => {
    const now = Date.now();
    const remainingMs = nextFavoriteActionAtRef.current - now;
    if (remainingMs > 0) {
      const remainingSeconds = Math.max(1, Math.ceil(remainingMs / 1000));
      toast({
        title: t('vault.favoriteCooldown.title', { defaultValue: 'Bitte kurz warten' }),
        description: t('vault.favoriteCooldown.description', {
          defaultValue: 'Favoriten werden gerade verschlüsselt gespeichert. Du kannst in {{count}} Sekunden weitermachen.',
          count: remainingSeconds,
        }),
      });
      return;
    }

    nextFavoriteActionAtRef.current = now + FAVORITE_ACTION_COOLDOWN_MS;
    const nextFavorite = !isItemFavorite(item);
    const sourcePlaintext = parseVerifiedPlaintextObject(opLogLocalVaultState?.recordsById.get(item.id) as LocalVerifiedRecord | undefined);
    const plaintext = itemPlaintextFromVaultItem(item, { isFavorite: nextFavorite }, sourcePlaintext);
    if (!plaintext) {
      nextFavoriteActionAtRef.current = 0;
      return;
    }

    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        is_favorite: nextFavorite,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, isFavorite: nextFavorite }
          : currentItem.decryptedData,
      };
    }));
    markItemRecentlyUsed(item.id);

    const result = await opLogUpdateItem(item.id, plaintext);
    if (!result.error) {
      return;
    }

    nextFavoriteActionAtRef.current = 0;
    setItems((current) => current.map((currentItem) => {
      if (currentItem.id !== item.id) {
        return currentItem;
      }
      return {
        ...currentItem,
        is_favorite: !nextFavorite,
        decryptedData: currentItem.decryptedData
          ? { ...currentItem.decryptedData, isFavorite: !nextFavorite }
          : currentItem.decryptedData,
      };
    }));
    toast({
      variant: 'destructive',
      title: t('common.error'),
      description: result.error.message,
    });
  }, [markItemRecentlyUsed, opLogLocalVaultState, opLogUpdateItem, t, toast]);

  const copySecretFromRow = useCallback(async (item: VaultItem, value: string | null | undefined, type: 'Username' | 'Password') => {
    if (!value || (opLogVerifiedItemIds !== null && !opLogVerifiedItemIds.has(item.id))) {
      return;
    }

    try {
      await writeClipboard(value);
      markItemRecentlyUsed(item.id);
      toast({
        title: t('vault.copied'),
        description: `${t(`vault.copied${type}`)} ${t('vault.clipboardAutoClear')}`,
      });
    } catch {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: t('vault.copyFailed'),
      });
    }
  }, [markItemRecentlyUsed, opLogVerifiedItemIds, t, toast]);

  const toggleCategoryCollapsed = useCallback((categoryId: string) => {
    setCollapsedCategoryIds((current) => {
      const next = new Set(current);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  }, []);

  const consumeSuppressedCategoryToggle = useCallback((categoryId: string): boolean => {
    const suppressed = suppressedCategoryToggleRef.current;
    if (!suppressed) {
      return false;
    }
    if (suppressed.until < Date.now()) {
      suppressedCategoryToggleRef.current = null;
      return false;
    }
    if (suppressed.categoryId !== categoryId) {
      return false;
    }
    suppressedCategoryToggleRef.current = null;
    return true;
  }, []);

  const getDraggedVaultItemId = useCallback((event: React.DragEvent): string => (
    event.dataTransfer.getData(VAULT_ITEM_DRAG_MIME)
    || event.dataTransfer.getData('text/plain')
  ), []);

  const handleCategoryDrop = useCallback((categoryId: string, event: React.DragEvent) => {
    event.preventDefault();
    event.stopPropagation();
    suppressedCategoryToggleRef.current = { categoryId, until: Date.now() + 500 };
    setNativeDraggingItemId(null);
    setDropTargetCategoryId(null);
    const itemId = getDraggedVaultItemId(event);
    if (!itemId) {
      return;
    }
    void moveItemToCategory(itemId, categoryId);
  }, [getDraggedVaultItemId, moveItemToCategory]);

  const setPointerDragState = useCallback((nextState: PointerDragState | null) => {
    pointerDragRef.current = nextState;
    setPointerDrag(nextState);
  }, []);

  const clearPointerDragTimer = useCallback(() => {
    if (pointerDragTimerRef.current !== null) {
      window.clearTimeout(pointerDragTimerRef.current);
      pointerDragTimerRef.current = null;
    }
  }, []);

  const resolveCategoryDropIdAtPoint = useCallback((x: number, y: number): string | null => {
    if (typeof document === 'undefined') {
      return null;
    }

    const element = document.elementFromPoint(x, y);
    const dropTarget = element?.closest<HTMLElement>('[data-vault-category-drop-id]');
    return dropTarget?.dataset.vaultCategoryDropId ?? null;
  }, []);

  const releasePointerCapture = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    try {
      event.currentTarget.releasePointerCapture(event.pointerId);
    } catch {
      // Some test and WebView runtimes expose Pointer Events without capture support.
    }
  }, []);

  const cancelPointerDrag = useCallback((event?: ReactPointerEvent<HTMLElement>) => {
    clearPointerDragTimer();
    if (event) {
      releasePointerCapture(event);
    }
    setDropTargetCategoryId(null);
    setPointerDragState(null);
  }, [clearPointerDragTimer, releasePointerCapture, setPointerDragState]);

  const startPointerDrag = useCallback((item: VaultItem, event: ReactPointerEvent<HTMLElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    clearPointerDragTimer();
    const originX = Number.isFinite(event.clientX) ? event.clientX : 0;
    const originY = Number.isFinite(event.clientY) ? event.clientY : 0;
    const activeImmediately = event.pointerType !== 'touch';
    const initialDropCategoryId = activeImmediately
      ? resolveCategoryDropIdAtPoint(originX, originY)
      : null;

    const initialState: PointerDragState = {
      itemId: item.id,
      title: getItemTitle(item),
      pointerId: event.pointerId,
      pointerType: event.pointerType,
      active: activeImmediately,
      originX,
      originY,
      x: originX,
      y: originY,
      dropCategoryId: initialDropCategoryId,
    };
    setPointerDragState(initialState);
    if (activeImmediately) {
      setDropTargetCategoryId(initialDropCategoryId);
    }

    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // Pointer capture is best-effort; native browser drag remains available for mouse users.
    }

    if (activeImmediately) {
      return;
    }

    pointerDragTimerRef.current = window.setTimeout(() => {
      const current = pointerDragRef.current;
      if (!current || current.pointerId !== event.pointerId) {
        return;
      }

      const dropCategoryId = resolveCategoryDropIdAtPoint(current.x, current.y);
      setPointerDragState({
        ...current,
        active: true,
        dropCategoryId,
      });
      setDropTargetCategoryId(dropCategoryId);
    }, TOUCH_DRAG_ACTIVATION_MS);
  }, [clearPointerDragTimer, resolveCategoryDropIdAtPoint, setPointerDragState]);

  const handlePointerDragMove = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    const current = pointerDragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }

    const x = Number.isFinite(event.clientX) ? event.clientX : current.x;
    const y = Number.isFinite(event.clientY) ? event.clientY : current.y;
    const deltaX = x - current.originX;
    const deltaY = y - current.originY;
    const movedDistance = Math.hypot(deltaX, deltaY);
    if (!current.active && movedDistance > TOUCH_DRAG_MOVE_THRESHOLD_PX) {
      cancelPointerDrag(event);
      return;
    }

    const dropCategoryId = current.active
      ? resolveCategoryDropIdAtPoint(x, y)
      : current.dropCategoryId;
    const nextState: PointerDragState = {
      ...current,
      x,
      y,
      dropCategoryId,
    };
    setPointerDragState(nextState);

    if (current.active) {
      event.preventDefault();
      event.stopPropagation();
      scrollViewportForDrag(y);
      setDropTargetCategoryId(dropCategoryId);
    }
  }, [cancelPointerDrag, resolveCategoryDropIdAtPoint, setPointerDragState]);

  const completePointerDrag = useCallback((event: ReactPointerEvent<HTMLElement>) => {
    const current = pointerDragRef.current;
    if (!current || current.pointerId !== event.pointerId) {
      return;
    }

    clearPointerDragTimer();
    releasePointerCapture(event);
    setPointerDragState(null);
    setDropTargetCategoryId(null);

    if (!current.active) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    const x = Number.isFinite(event.clientX) ? event.clientX : current.x;
    const y = Number.isFinite(event.clientY) ? event.clientY : current.y;
    const dropCategoryId = current.dropCategoryId ?? resolveCategoryDropIdAtPoint(x, y);
    if (dropCategoryId) {
      void moveItemToCategory(current.itemId, dropCategoryId);
    }
  }, [
    clearPointerDragTimer,
    moveItemToCategory,
    releasePointerCapture,
    resolveCategoryDropIdAtPoint,
    setPointerDragState,
  ]);

  useEffect(() => () => {
    clearPointerDragTimer();
  }, [clearPointerDragTimer]);

  const visibleEntries = useMemo<RenderableVaultListEntry[]>(() => {
    return items.reduce<RenderableVaultListEntry[]>((entries, item) => {
      const quarantine = quarantinedItemsById.get(item.id);
      if (quarantine) {
        if (canRenderInlineQuarantine(item, quarantine)) {
          entries.push({ kind: 'quarantined', item, quarantine });
        }
        return entries;
      }

      if (!item.decryptedData) {
        return entries;
      }

      // Phase 10: if OpLog UI is active, exclude non-verified records from search results.
      if (opLogVerifiedItemIds && !opLogVerifiedItemIds.has(item.id)) {
        return entries;
      }

      const resolvedCategoryId = item.decryptedData.categoryId ?? item.category_id;
      const resolvedItemType = item.decryptedData.itemType || item.item_type;
      const resolvedIsFavorite = typeof item.decryptedData.isFavorite === 'boolean'
        ? item.decryptedData.isFavorite
        : !!item.is_favorite;

      if (resolvedItemType === 'totp') {
        return entries;
      }

      const hooks = getServiceHooks();
      const itemIsDecoy = hooks.isDecoyItem
        ? hooks.isDecoyItem(item.decryptedData as unknown as Record<string, unknown>)
        : false;

      if (isDuressMode && !itemIsDecoy) {
        return entries;
      }
      if (!isDuressMode && itemIsDecoy) {
        return entries;
      }

      if (categoryId && resolvedCategoryId !== categoryId) {
        return entries;
      }

      if (filter === 'passwords' && resolvedItemType !== 'password') {
        return entries;
      }
      if (filter === 'notes' && resolvedItemType !== 'note') {
        return entries;
      }
      if (filter === 'favorites' && !resolvedIsFavorite) {
        return entries;
      }

      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const resolvedTitle = item.decryptedData.title || item.title;
        const resolvedUrl = item.decryptedData.websiteUrl || item.website_url;
        const matchTitle = resolvedTitle.toLowerCase().includes(query);
        const matchUrl = resolvedUrl?.toLowerCase().includes(query);
        const matchUsername = item.decryptedData.username?.toLowerCase().includes(query);
        if (!matchTitle && !matchUrl && !matchUsername) {
          return entries;
        }
      }

      entries.push({ kind: 'item', item });
      return entries;
    }, []);
  }, [
    items,
    quarantinedItemsById,
    canRenderInlineQuarantine,
    filter,
    categoryId,
    searchQuery,
    isDuressMode,
    opLogVerifiedItemIds,
  ]);

  const visibleItemEntries = useMemo(
    () => visibleEntries.filter(
      (entry): entry is Extract<RenderableVaultListEntry, { kind: 'item' }> => entry.kind === 'item',
    ),
    [visibleEntries],
  );

  const previewItem = useMemo(
    () => visibleItemEntries.find((entry) => entry.item.id === previewItemId)?.item ?? null,
    [previewItemId, visibleItemEntries],
  );

  const deletePreviewItem = useMemo(
    () => visibleItemEntries.find((entry) => entry.item.id === deletePreviewItemId)?.item ?? null,
    [deletePreviewItemId, visibleItemEntries],
  );

  useEffect(() => {
    if (previewItemId && !visibleItemEntries.some((entry) => entry.item.id === previewItemId)) {
      setPreviewItemId(null);
    }
  }, [previewItemId, visibleItemEntries]);

  useEffect(() => {
    if (!focusItemId) {
      lastHandledFocusItemIdRef.current = null;
      return;
    }

    if (lastHandledFocusItemIdRef.current === focusItemId) {
      return;
    }

    const focusedEntry = visibleItemEntries.find((entry) => entry.item.id === focusItemId);
    if (!focusedEntry) {
      return;
    }

    lastHandledFocusItemIdRef.current = focusItemId;
    markItemRecentlyUsed(focusItemId);
    setPreviewItemId(focusItemId);
    setHighlightedItemId(focusItemId);

    window.requestAnimationFrame(() => {
      itemElementRefs.current.get(focusItemId)?.scrollIntoView({
        block: 'center',
        behavior: 'smooth',
      });
    });

    if (focusHighlightTimerRef.current !== null) {
      window.clearTimeout(focusHighlightTimerRef.current);
    }
    focusHighlightTimerRef.current = window.setTimeout(() => {
      setHighlightedItemId((current) => (current === focusItemId ? null : current));
      focusHighlightTimerRef.current = null;
    }, FOCUS_HIGHLIGHT_MS);
  }, [focusItemId, markItemRecentlyUsed, visibleItemEntries]);

  const confirmDeletePreviewItem = useCallback(async () => {
    if (!deletePreviewItem) {
      return;
    }

    setDeletingPreviewItem(true);
    const result = await opLogDeleteItem(deletePreviewItem.id);
    setDeletingPreviewItem(false);

    if (result.error) {
      toast({
        variant: 'destructive',
        title: t('common.error'),
        description: result.error.message,
      });
      return;
    }

    setDeletePreviewItemId(null);
    setPreviewItemId(null);
    setItems((current) => current.filter((item) => item.id !== deletePreviewItem.id));
    toast({
      title: t('common.success'),
      description: t('vault.itemDeleted'),
    });
  }, [deletePreviewItem, opLogDeleteItem, t, toast]);

  const shouldRenderDashboardSections =
    viewMode === 'grid'
    && filter === 'all'
    && !categoryId
    && searchQuery.trim() === ''
    && visibleItemEntries.length > 1;

  const favoriteEntries = useMemo(
    () => visibleItemEntries
      .filter(({ item }) => item.decryptedData?.isFavorite ?? item.is_favorite),
    [visibleItemEntries],
  );

  const recentlyUsedEntries = useMemo(() => {
    const byId = new Map(visibleItemEntries.map((entry) => [entry.item.id, entry]));
    const explicitRecentEntries = recentlyCopiedItemIds
      .map((id) => byId.get(id))
      .filter((entry): entry is Extract<RenderableVaultListEntry, { kind: 'item' }> => !!entry);
    const explicitRecentIds = new Set(explicitRecentEntries.map((entry) => entry.item.id));

    const fallbackEntries = [...visibleItemEntries]
      .filter((entry) => !explicitRecentIds.has(entry.item.id))
      .sort((left, right) => right.item.updated_at.localeCompare(left.item.updated_at))
      .slice(0, RECENT_SECTION_LIMIT - explicitRecentEntries.length);

    return [...explicitRecentEntries, ...fallbackEntries].slice(0, RECENT_SECTION_LIMIT);
  }, [recentlyCopiedItemIds, visibleItemEntries]);

  const groupedCategorySections = useMemo(() => (
    categorySummaries
      .map((category) => ({
        category,
        entries: visibleItemEntries.filter((entry) => getItemCategoryId(entry.item) === category.id),
      }))
      .filter((section) => section.entries.length > 0)
  ), [categorySummaries, visibleItemEntries]);

  const uncategorizedEntries = useMemo(() => (
    visibleItemEntries.filter((entry) => !getItemCategoryId(entry.item))
  ), [visibleItemEntries]);

  const renderPointerDragHandle = useCallback((item: VaultItem, className?: string) => (
    <button
      type="button"
      className={cn(
        'inline-flex h-10 w-10 shrink-0 touch-none items-center justify-center rounded-md border border-border/35 bg-background/80 text-muted-foreground shadow-sm backdrop-blur transition-colors hover:border-primary/55 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/45 sm:h-8 sm:w-8',
        className,
      )}
      aria-label={t('vault.dragDrop.dragHandle', { defaultValue: 'Eintrag verschieben' })}
      onClick={(event) => event.stopPropagation()}
      onPointerDown={(event) => startPointerDrag(item, event)}
      onPointerMove={handlePointerDragMove}
      onPointerUp={completePointerDrag}
      onPointerCancel={cancelPointerDrag}
    >
      <GripVertical className="h-4 w-4" aria-hidden="true" />
    </button>
  ), [
    cancelPointerDrag,
    completePointerDrag,
    handlePointerDragMove,
    startPointerDrag,
    t,
  ]);

  const renderItemCard = useCallback((
    entry: Extract<RenderableVaultListEntry, { kind: 'item' }>,
    options?: { draggable?: boolean },
  ) => (
    <div
      key={entry.item.id}
      ref={(element) => setItemElementRef(entry.item.id, element)}
      data-vault-item-id={entry.item.id}
      className={cn(
        'group/drag relative rounded-2xl transition-[box-shadow,transform] duration-500',
        highlightedItemId === entry.item.id && 'ring-2 ring-primary/70 shadow-[0_0_0_1px_hsl(var(--primary)/0.24),0_0_32px_hsl(var(--primary)/0.28)]',
      )}
      draggable={options?.draggable ?? true}
      onDragStart={(event) => {
        if (options?.draggable === false) {
          event.preventDefault();
          return;
        }
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData(VAULT_ITEM_DRAG_MIME, entry.item.id);
        event.dataTransfer.setData('text/plain', entry.item.id);
        setNativeDraggingItemId(entry.item.id);
      }}
      onDragEnd={() => {
        setNativeDraggingItemId(null);
        setDropTargetCategoryId(null);
      }}
    >
      {renderPointerDragHandle(entry.item, 'absolute -left-2 top-2 z-20 opacity-0 sm:group-hover/drag:opacity-100 sm:focus-visible:opacity-100')}
      <VaultItemCard
        item={entry.item}
        viewMode={viewMode}
        onEdit={() => openItemPreview(entry.item)}
        onSecretCopied={markItemRecentlyUsed}
        canCopySecrets={
          opLogVerifiedItemIds === null || opLogVerifiedItemIds.has(entry.item.id)
        }
      />
    </div>
  ), [
    highlightedItemId,
    markItemRecentlyUsed,
    openItemPreview,
    opLogVerifiedItemIds,
    renderPointerDragHandle,
    setItemElementRef,
    viewMode,
  ]);

  const renderTableRow = useCallback((
    entry: Extract<RenderableVaultListEntry, { kind: 'item' }>,
    options?: { showCategory?: boolean },
  ) => {
    const { item } = entry;
    const title = getItemTitle(item);
    const websiteUrl = getItemWebsiteUrl(item);
    const username = getItemUsername(item);
    const password = item.decryptedData?.password ?? null;
    const favorite = isItemFavorite(item);
    const resolvedCategoryId = getItemCategoryId(item);
    const canCopy = opLogVerifiedItemIds === null || opLogVerifiedItemIds.has(item.id);

    return (
      <div
        key={item.id}
        ref={(element) => setItemElementRef(item.id, element)}
        data-vault-item-id={item.id}
        draggable
        onDragStart={(event) => {
          event.dataTransfer.effectAllowed = 'move';
          event.dataTransfer.setData(VAULT_ITEM_DRAG_MIME, item.id);
          event.dataTransfer.setData('text/plain', item.id);
          setNativeDraggingItemId(item.id);
        }}
        onDragEnd={() => {
          setNativeDraggingItemId(null);
          setDropTargetCategoryId(null);
        }}
        className={cn(
          'group grid min-h-14 cursor-pointer grid-cols-[minmax(0,1fr)_auto] items-center gap-3 border-t border-[hsl(var(--border)/0.22)] px-3 py-2.5 transition-all duration-500 ease-out hover:bg-white/[0.035] md:grid-cols-[minmax(210px,1.3fr)_minmax(120px,0.9fr)_minmax(110px,0.8fr)_minmax(110px,0.8fr)_132px]',
          highlightedItemId === item.id && 'relative z-10 bg-[hsl(var(--primary)/0.08)] ring-2 ring-primary/70 shadow-[0_0_0_1px_hsl(var(--primary)/0.24),0_0_32px_hsl(var(--primary)/0.28)]',
        )}
        onClick={() => openItemPreview(item)}
      >
        <div className="flex min-w-0 items-center gap-2.5">
          {renderPointerDragHandle(item, 'border-transparent bg-transparent shadow-none')}
          <VaultIcon title={title} websiteUrl={websiteUrl} className="h-7 w-7 shrink-0" />
          <div className="min-w-0">
            <button
              type="button"
              className="block max-w-full truncate text-left text-sm font-medium text-foreground hover:text-primary"
              onClick={(event) => {
                event.stopPropagation();
                openItemPreview(item);
              }}
            >
              {title}
            </button>
            {options?.showCategory && resolvedCategoryId && (
              <p className="mt-0.5 truncate text-[11px] text-muted-foreground md:hidden">
                {categoryNameById.get(resolvedCategoryId) ?? t('categories.category', { defaultValue: 'Kategorie' })}
              </p>
            )}
          </div>
        </div>

        <span className="hidden min-w-0 truncate text-sm text-muted-foreground md:block">
          {username || '—'}
        </span>
        <span className="hidden font-mono text-sm tracking-[0.18em] text-muted-foreground md:block">
          {password ? '••••••••••' : '—'}
        </span>
        <span className="hidden min-w-0 text-sm text-muted-foreground md:block">
          {options?.showCategory && resolvedCategoryId
            ? categoryNameById.get(resolvedCategoryId) ?? '—'
            : formatRelativeUpdatedAt(item.updated_at)}
        </span>

        <div className="flex items-center justify-end gap-1">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className={cn(
              'h-10 w-10 text-muted-foreground hover:text-amber-300 sm:h-8 sm:w-8',
              favorite && 'text-amber-400',
            )}
            aria-label={favorite
              ? t('vault.actions.removeFavorite', { defaultValue: 'Favorit entfernen' })
              : t('vault.actions.addFavorite', { defaultValue: 'Als Favorit markieren' })}
            onClick={(event) => {
              event.stopPropagation();
              void toggleItemFavorite(item);
            }}
          >
            <Star className={cn('h-4 w-4', favorite && 'fill-current')} />
          </Button>
          {username && canCopy && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
              aria-label={t('vault.actions.copyUsername')}
              onClick={(event) => {
                event.stopPropagation();
                void copySecretFromRow(item, username, 'Username');
              }}
            >
              <Copy className="h-4 w-4" />
            </Button>
          )}
          {password && canCopy && (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
              aria-label={t('vault.actions.copyPassword')}
              onClick={(event) => {
                event.stopPropagation();
                void copySecretFromRow(item, password, 'Password');
              }}
            >
              <KeyRound className="h-4 w-4" />
            </Button>
          )}
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-10 w-10 text-muted-foreground hover:text-primary sm:h-8 sm:w-8"
            aria-label={t('common.edit')}
            onClick={(event) => {
              event.stopPropagation();
              editItemFromPreview(item.id);
            }}
          >
            <Edit className="h-4 w-4" />
          </Button>
        </div>
      </div>
    );
  }, [
    categoryNameById,
    copySecretFromRow,
    editItemFromPreview,
    highlightedItemId,
    openItemPreview,
    opLogVerifiedItemIds,
    renderPointerDragHandle,
    setItemElementRef,
    t,
    toggleItemFavorite,
  ]);

  const handleFavoriteScrollerPointerDown = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) {
      return;
    }

    const target = event.target as HTMLElement | null;
    if (target?.closest('button,a,input,textarea,select,[role="button"]')) {
      return;
    }

    const scroller = favoriteScrollerRef.current;
    if (!scroller) {
      return;
    }

    favoriteScrollDragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      scrollLeft: scroller.scrollLeft,
      dragging: false,
    };
    try {
      scroller.setPointerCapture(event.pointerId);
    } catch {
      favoriteScrollDragRef.current = null;
    }
  }, []);

  const handleFavoriteScrollerPointerMove = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const current = favoriteScrollDragRef.current;
    const scroller = favoriteScrollerRef.current;
    if (!current || !scroller || current.pointerId !== event.pointerId) {
      return;
    }

    const deltaX = event.clientX - current.startX;
    if (Math.abs(deltaX) > 4) {
      current.dragging = true;
    }
    if (!current.dragging) {
      return;
    }

    event.preventDefault();
    scroller.scrollLeft = current.scrollLeft - deltaX;
  }, []);

  const handleFavoriteScrollerPointerEnd = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const scroller = favoriteScrollerRef.current;
    if (scroller) {
      try {
        scroller.releasePointerCapture(event.pointerId);
      } catch {
        favoriteScrollDragRef.current = null;
      }
    }
    favoriteScrollDragRef.current = null;
  }, []);

  const renderFavoriteSection = useCallback(() => {
    if (favoriteEntries.length === 0) {
      return null;
    }

    const hiddenCount = Math.max(0, favoriteEntries.length - favoriteCollapsedLimit);
    const entries = favoriteExpanded
      ? favoriteEntries
      : favoriteEntries.slice(0, favoriteCollapsedLimit);

    return (
      <section className="space-y-3">
        <div className="flex items-center justify-between gap-3 px-1">
          <div className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Pin className="h-4 w-4 text-primary" aria-hidden="true" />
            <span>{t('vault.sections.favorites', { defaultValue: 'Favoriten' })}</span>
          </div>
          {hiddenCount > 0 && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-8 rounded-full px-3 text-xs text-primary hover:text-primary"
              onClick={() => setFavoriteExpanded((expanded) => !expanded)}
            >
              {favoriteExpanded
                ? t('vault.sections.showFewerFavorites', { defaultValue: 'Weniger anzeigen' })
                : t('vault.sections.showMoreFavorites', {
                  defaultValue: '+ {{count}} weitere anzeigen',
                  count: hiddenCount,
                })}
            </Button>
          )}
        </div>
        {favoriteExpanded ? (
          <>
            {/* Mobile / tablet: vertikales Grid — versteckt ab lg */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:hidden">
              {entries.map((entry) => (
                <div key={entry.item.id}>
                  {renderItemCard(entry, { draggable: false })}
                </div>
              ))}
            </div>
            {/* Desktop lg+: horizontaler Wisch-Carousel — versteckt unter lg */}
            <div
              ref={favoriteScrollerRef}
              className="scrollbar-hide hidden cursor-grab touch-pan-x select-none gap-4 overflow-x-auto pb-2 pr-4 active:cursor-grabbing lg:flex"
              onPointerDown={handleFavoriteScrollerPointerDown}
              onPointerMove={handleFavoriteScrollerPointerMove}
              onPointerUp={handleFavoriteScrollerPointerEnd}
              onPointerCancel={handleFavoriteScrollerPointerEnd}
              onPointerLeave={handleFavoriteScrollerPointerEnd}
            >
              {entries.map((entry) => (
                <div
                  key={entry.item.id}
                  className="min-w-[240px] max-w-[280px] flex-[0_0_72%] lg:basis-[240px] xl:basis-[220px]"
                >
                  {renderItemCard(entry, { draggable: false })}
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
            {entries.map((entry) => renderItemCard(entry))}
          </div>
        )}
      </section>
    );
  }, [
    favoriteCollapsedLimit,
    favoriteEntries,
    favoriteExpanded,
    handleFavoriteScrollerPointerDown,
    handleFavoriteScrollerPointerEnd,
    handleFavoriteScrollerPointerMove,
    renderItemCard,
    t,
  ]);

  const renderTableHeader = useCallback((options?: { fourthColumn?: string }) => (
    <div className="hidden grid-cols-[minmax(210px,1.3fr)_minmax(120px,0.9fr)_minmax(110px,0.8fr)_minmax(110px,0.8fr)_132px] gap-3 px-3 py-2 text-[11px] font-medium uppercase tracking-[0.08em] text-muted-foreground md:grid">
      <span>{t('vault.table.name', { defaultValue: 'Name' })}</span>
      <span>{t('vault.table.username', { defaultValue: 'Benutzername' })}</span>
      <span>{t('vault.table.password', { defaultValue: 'Passwort' })}</span>
      <span>{options?.fourthColumn ?? t('vault.table.lastUsed', { defaultValue: 'Zuletzt verwendet' })}</span>
      <span className="text-right">{t('vault.table.actions', { defaultValue: 'Aktionen' })}</span>
    </div>
  ), [t]);

  const renderVaultTable = useCallback((
    entries: Extract<RenderableVaultListEntry, { kind: 'item' }>[],
    options?: { showHeader?: boolean; showCategory?: boolean; fourthColumn?: string },
  ) => (
    <div className="overflow-hidden rounded-xl border border-[hsl(var(--border)/0.32)] bg-[hsl(var(--el-1)/0.72)] shadow-[0_18px_48px_hsl(0_0%_0%/0.24)] backdrop-blur transition-all duration-200 ease-out">
      {options?.showHeader && renderTableHeader({ fourthColumn: options.fourthColumn })}
      {entries.map((entry) => renderTableRow(entry, { showCategory: options?.showCategory }))}
    </div>
  ), [renderTableHeader, renderTableRow]);

  const renderRecentSection = useCallback(() => {
    if (recentlyUsedEntries.length === 0) {
      return null;
    }

    const columns = [
      recentlyUsedEntries.slice(0, 4),
      recentlyUsedEntries.slice(4, 8),
    ].filter((column) => column.length > 0);

    return (
      <section className={cn('space-y-3', favoriteEntries.length > 0 && 'border-t border-border/35 pt-5')}>
        <div className="flex items-center gap-2 px-1 text-sm font-semibold text-foreground">
          <Clock3 className="h-4 w-4 text-primary" aria-hidden="true" />
          <span>{t('vault.sections.recentlyUsed', { defaultValue: 'Zuletzt verwendet' })}</span>
        </div>
        <div className={cn('grid gap-3', columns.length > 1 && 'xl:grid-cols-2')}>
          {columns.map((column, index) => (
            <div key={`recent-${index}`}>
              {renderVaultTable(column)}
            </div>
          ))}
        </div>
      </section>
    );
  }, [favoriteEntries.length, recentlyUsedEntries, renderVaultTable, t]);

  const renderGroupedAllEntries = useCallback(() => {
    const hasCategorizedEntries = groupedCategorySections.length > 0;
    const hasUncategorizedEntries = uncategorizedEntries.length > 0;

    if (!hasCategorizedEntries && !hasUncategorizedEntries) {
      return null;
    }

    return (
      <section className={cn(
        'space-y-4',
        (favoriteEntries.length > 0 || recentlyUsedEntries.length > 0) && 'border-t border-border/35 pt-5',
      )}>
        <div className="flex items-center justify-between gap-3 px-1">
          <h2 className="text-sm font-semibold text-foreground">
            {t('vault.sections.allEntries', { defaultValue: 'Alle Einträge' })}
          </h2>
          <span className="text-xs text-muted-foreground">
            {t('vault.sections.entryCount', {
              defaultValue: '{{count}} Einträge',
              count: visibleItemEntries.length,
            })}
          </span>
        </div>

        {groupedCategorySections.map(({ category, entries }) => {
          const collapsed = collapsedCategoryIds.has(category.id);
          const isDropTarget = dropTargetCategoryId === category.id;

          return (
            <div
              key={category.id}
              data-vault-category-drop-id={category.id}
              className={cn(
                'overflow-hidden rounded-xl border border-[hsl(var(--border)/0.32)] bg-[hsl(var(--el-1)/0.72)] backdrop-blur transition-colors',
                isDropTarget && 'border-primary/70 ring-2 ring-primary/30',
              )}
              onDragEnter={(event) => {
                event.preventDefault();
                event.dataTransfer.dropEffect = 'move';
                setDropTargetCategoryId(category.id);
              }}
              onDragOver={(event) => {
                event.preventDefault();
                event.dataTransfer.dropEffect = 'move';
                setDropTargetCategoryId(category.id);
              }}
              onDragLeave={() => setDropTargetCategoryId((current) => (
                current === category.id ? null : current
              ))}
              onDrop={(event) => handleCategoryDrop(category.id, event)}
            >
              <button
                type="button"
                className="flex w-full items-center justify-between gap-3 px-3 py-3 text-left transition-colors hover:bg-white/[0.035]"
                onClick={() => {
                  if (consumeSuppressedCategoryToggle(category.id)) {
                    return;
                  }
                  toggleCategoryCollapsed(category.id);
                }}
              >
                <span className="flex min-w-0 items-center gap-2">
                  {collapsed ? <ChevronRight className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                  <span className="truncate text-sm font-semibold text-foreground">{category.name}</span>
                  <span className="rounded-md border border-primary/35 bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                    {entries.length}
                  </span>
                </span>
                <span className="text-xs text-muted-foreground">
                  {t('vault.dragDrop.dropHint', { defaultValue: 'Einträge hier ablegen' })}
                </span>
              </button>
              {!collapsed && (
                <>
                  {renderTableHeader()}
                  {entries.map((entry) => renderTableRow(entry))}
                </>
              )}
            </div>
          );
        })}

        {uncategorizedEntries.length > 0 && (
          <div className="space-y-3">
            {(hasCategorizedEntries || favoriteEntries.length > 0 || recentlyUsedEntries.length > 0) && (
              <div className="px-1 text-sm font-semibold text-foreground">
                {t('vault.sections.uncategorized', { defaultValue: 'Ohne Kategorie' })}
              </div>
            )}
            {renderVaultTable(uncategorizedEntries, {
              showHeader: hasCategorizedEntries,
              showCategory: false,
            })}
          </div>
        )}
      </section>
    );
  }, [
    collapsedCategoryIds,
    dropTargetCategoryId,
    favoriteEntries.length,
    groupedCategorySections,
    handleCategoryDrop,
    recentlyUsedEntries.length,
    renderTableHeader,
    renderTableRow,
    renderVaultTable,
    t,
    consumeSuppressedCategoryToggle,
    toggleCategoryCollapsed,
    uncategorizedEntries,
    visibleItemEntries.length,
  ]);

  const inlineQuarantinedIds = useMemo(
    () => new Set(
      visibleEntries
        .filter((entry): entry is Extract<RenderableVaultListEntry, { kind: 'quarantined' }> => entry.kind === 'quarantined')
        .map((entry) => entry.quarantine.id),
    ),
    [visibleEntries],
  );

  const panelQuarantinedItems = useMemo(
    () => {
      if (!hasGroupedQuarantine || !canRenderGroupedQuarantine) {
        return [];
      }

      return quarantinedItems.filter(
        (item) => !inlineQuarantinedIds.has(item.id) && !activeIgnoredQuarantineIds.has(item.id),
      );
    },
    [
      activeIgnoredQuarantineIds,
      canRenderGroupedQuarantine,
      hasGroupedQuarantine,
      inlineQuarantinedIds,
      quarantinedItems,
    ],
  );
  const restorablePanelItems = useMemo(
    () => panelQuarantinedItems.filter(
      (item) => quarantineResolutionById[item.id]?.canRestore,
    ),
    [panelQuarantinedItems, quarantineResolutionById],
  );

  const handleIgnoreGroupedQuarantine = useCallback(() => {
    persistIgnoredQuarantine({
      ...ignoredQuarantineById,
      ...Object.fromEntries(
        panelQuarantinedItems.map((item) => [item.id, getQuarantineIgnoreToken(item)]),
      ),
    });
    setShowIgnoredQuarantine(false);
  }, [ignoredQuarantineById, panelQuarantinedItems, persistIgnoredQuarantine]);

  const handleRestoreAllVisible = useCallback(async () => {
    const itemsToRestore = restorablePanelItems;
    if (itemsToRestore.length === 0) {
      setBulkRestoreConfirmOpen(false);
      return;
    }

    setBulkRestoreConfirmOpen(false);
    setBulkRestoreProgress({
      open: true,
      status: 'running',
      total: itemsToRestore.length,
      completed: 0,
      failed: 0,
      currentItemId: itemsToRestore[0].id,
      lastError: null,
    });

    let completed = 0;
    let failed = 0;
    let lastError: string | null = null;

    for (const item of itemsToRestore) {
      setBulkRestoreProgress((current) => ({
        ...current,
        currentItemId: item.id,
      }));

      const result = await opLogRestoreRecord(item.id);
      if (result.error) {
        failed += 1;
        lastError = result.error.message;
      } else {
        completed += 1;
      }

      setBulkRestoreProgress((current) => ({
        ...current,
        completed,
        failed,
        lastError,
      }));
    }

    setBulkRestoreProgress((current) => ({
      ...current,
      status: failed > 0 ? 'failed' : 'success',
      currentItemId: null,
      lastError,
    }));
  }, [opLogRestoreRecord, restorablePanelItems]);

  const renderableItemCount = items.filter((item) => item.decryptedData).length;

  if ((loading || decrypting) && items.length === 0 && quarantinedItems.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-muted-foreground">
        <Loader2 className="mb-4 h-8 w-8 animate-spin" />
        <p>{decrypting ? t('vault.items.decrypting') : t('common.loading')}</p>
      </div>
    );
  }

  if (items.length === 0 && quarantinedItems.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-center">
        <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
          <Shield className="h-8 w-8 text-primary/60" />
        </div>
        <h3 className="mb-2 text-lg font-medium">{t('vault.empty.title')}</h3>
        <p className="mb-4 max-w-sm text-muted-foreground">
          {t('vault.empty.description')}
        </p>
        <Button onClick={() => onEditItem('')}>
          <Plus className="mr-2 h-4 w-4" />
          {t('vault.empty.action')}
        </Button>
      </div>
    );
  }

  if (visibleEntries.length === 0 && quarantinedItems.length === 0) {
    return (
      <div className="flex h-64 flex-col items-center justify-center text-center">
        <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
          <KeyRound className="h-8 w-8 text-primary/60" />
        </div>
        <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
        <p className="max-w-sm text-muted-foreground">
          {t('vault.search.noResultsDescription')}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {(backgroundSyncing || lastCloudSyncAt || securityStatusLoading || (canRenderGroupedQuarantine && (hasGroupedQuarantine || revalidating))) && (
        <div className="flex items-center justify-end gap-2">
          {(backgroundSyncing || lastCloudSyncAt) && (
            <span
              className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-1)/0.78)] text-primary shadow-[0_0_24px_hsl(var(--primary)/0.08)]"
              title={backgroundSyncing
                ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
                : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
              aria-label={backgroundSyncing
                ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
                : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
            >
              <Cloud className={cn('h-4 w-4', backgroundSyncing && 'animate-pulse')} />
              <span className="sr-only">
                {backgroundSyncing
                  ? t('vault.items.cloudSyncing', { defaultValue: 'Synchronisiere mit Cloud...' })
                  : t('vault.items.cloudSyncedRecently', { defaultValue: 'Zuletzt synchronisiert vor wenigen Sekunden' })}
              </span>
            </span>
          )}
          {securityStatusLoading && (
            <span
              className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-emerald-300/25 bg-[hsl(var(--el-1)/0.78)] text-emerald-300 shadow-[0_0_24px_hsl(var(--success)/0.08)]"
              title={t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
              aria-label={t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
            >
              <ShieldCheck className="h-4 w-4 animate-pulse" />
              <span className="sr-only">
                {t('vault.oplog.loading', { defaultValue: 'Sicherheitsstatus wird geladen...' })}
              </span>
            </span>
          )}
          {canRenderGroupedQuarantine && (hasGroupedQuarantine || revalidating) && (
            <button
              type="button"
              disabled={revalidating}
              onClick={() => void revalidateRemoteIntegrity()}
              className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-1)/0.78)] text-emerald-300 shadow-[0_0_24px_hsl(var(--success)/0.08)] transition-colors hover:border-emerald-300/40 hover:bg-emerald-400/10 disabled:cursor-wait"
              title={revalidating
                ? t('vault.integrity.revalidatingEntries', { defaultValue: 'Prüfe Einträge...' })
                : t('vault.integrity.revalidationHint', { defaultValue: 'Die Liste nutzt zuerst den lokalen Stand und prüft danach kurz gegen den Server.' })}
              aria-label={revalidating
                ? t('vault.integrity.revalidatingEntries', { defaultValue: 'Prüfe Einträge...' })
                : t('vault.integrity.revalidationHint', { defaultValue: 'Die Liste nutzt zuerst den lokalen Stand und prüft danach kurz gegen den Server.' })}
            >
              <ShieldCheck className={cn('h-4 w-4', revalidating && 'animate-pulse')} />
            </button>
          )}
        </div>
      )}

      {canRenderGroupedQuarantine && hasIgnoredGroupedQuarantine && !showIgnoredQuarantine && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm">
          <p className="inline-flex items-center gap-2 text-amber-800 dark:text-amber-200">
            <TriangleAlert className="h-4 w-4" />
            {t('vault.integrity.ignoredQuarantineHint', {
              defaultValue: '{{count}} manipulierte Einträge sind in der Quarantäne einsehbar.',
              count: activeIgnoredQuarantinedItems.length,
            })}
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="border-amber-500/35"
            onClick={() => setShowIgnoredQuarantine(true)}
          >
            <Eye className="mr-2 h-4 w-4" />
            {t('vault.integrity.showIgnoredQuarantineAction', {
              defaultValue: 'Quarantäne anzeigen',
            })}
          </Button>
        </div>
      )}

      <VaultQuarantinePanel
        items={panelQuarantinedItems}
        ignoredItems={showIgnoredQuarantine ? activeIgnoredQuarantinedItems : []}
        onIgnoreItem={handleIgnoreQuarantineItem}
        onRestoreAll={
          restorablePanelItems.length > 0
            ? () => setBulkRestoreConfirmOpen(true)
            : undefined
        }
        restoreAllCount={restorablePanelItems.length}
        restoreAllDisabled={bulkRestoreProgress.open && bulkRestoreProgress.status === 'running'}
        onIgnoreAll={
          hasGroupedQuarantine && canRenderGroupedQuarantine && panelQuarantinedItems.length > 0
            ? handleIgnoreGroupedQuarantine
            : undefined
        }
      />

      {visibleEntries.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center text-center">
          <div className="mb-4 rounded-full border border-[hsl(var(--border)/0.35)] bg-[hsl(var(--el-2))] p-4">
            <KeyRound className="h-8 w-8 text-primary/60" />
          </div>
          {renderableItemCount === 0 ? (
            <>
              <h3 className="mb-2 text-lg font-medium">
                {t('vault.integrity.onlyQuarantinedTitle', {
                  defaultValue: 'Derzeit sind nur Einträge in Quarantäne vorhanden',
                })}
              </h3>
              <p className="max-w-sm text-muted-foreground">
                {t('vault.integrity.onlyQuarantinedDescription', {
                  defaultValue: 'Normale Einträge sind aktuell nicht verfügbar. Prüfe die Quarantänehinweise oben.',
                })}
              </p>
            </>
          ) : (
            <>
              <h3 className="mb-2 text-lg font-medium">{t('vault.search.noResults')}</h3>
              <p className="max-w-sm text-muted-foreground">
                {t('vault.search.noResultsDescription')}
              </p>
            </>
          )}
        </div>
      ) : shouldRenderDashboardSections ? (
        <div className="space-y-7">
          {renderFavoriteSection()}
          {renderRecentSection()}
          {renderGroupedAllEntries()}
        </div>
      ) : (
        <div
          className={cn(
            viewMode === 'grid'
              ? 'grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4'
              : 'flex flex-col gap-2',
          )}
        >
          {visibleEntries.map((entry) => (
            entry.kind === 'item' ? (
              renderItemCard(entry)
            ) : (
              <VaultQuarantinedItemCard
                key={entry.quarantine.id}
                itemId={entry.quarantine.id}
                reason={entry.quarantine.reason}
                viewMode={viewMode}
              />
            )
          ))}
        </div>
      )}

      {pointerDrag?.active && (
        <div
          className="pointer-events-none fixed z-[90] max-w-[min(280px,calc(100vw-2rem))] rounded-lg border border-primary/40 bg-background/90 px-3 py-2 text-sm font-medium text-foreground shadow-[0_18px_52px_hsl(0_0%_0%/0.45)] backdrop-blur-xl"
          style={{
            left: (Number.isFinite(pointerDrag.x) ? pointerDrag.x : 0) + 12,
            top: (Number.isFinite(pointerDrag.y) ? pointerDrag.y : 0) + 12,
          }}
        >
          <span className="block truncate">{pointerDrag.title}</span>
          <span className="text-xs text-primary">
            {t('vault.dragDrop.moving', { defaultValue: 'Verschieben' })}
          </span>
        </div>
      )}

      {previewItem && (
        <VaultItemPreviewPanel>
          <div className="flex items-start justify-between gap-3 rounded-2xl border border-border/30 bg-white/[0.015] p-3 shadow-[0_14px_34px_hsl(0_0%_0%/0.18)]">
            <div className="flex min-w-0 items-center gap-3">
              <VaultIcon
                title={getItemTitle(previewItem)}
                websiteUrl={getItemWebsiteUrl(previewItem)}
                className="h-12 w-12 rounded-xl"
                iconClassName="h-6 w-6"
              />
              <div className="min-w-0">
                <h3 className="truncate text-base font-semibold">{getItemTitle(previewItem)}</h3>
                <p className="truncate text-xs text-muted-foreground">
                  {getItemUsername(previewItem) || getItemWebsiteUrl(previewItem) || '—'}
                </p>
              </div>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0 text-muted-foreground hover:text-foreground"
              aria-label={t('common.close', { defaultValue: 'Schließen' })}
              onClick={() => {
                setDeletePreviewItemId(null);
                setPreviewItemId(null);
              }}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>

          <div className="mt-5 space-y-2 rounded-2xl border border-border/25 bg-white/[0.012] p-2">
            {getItemUsername(previewItem) && (opLogVerifiedItemIds === null || opLogVerifiedItemIds.has(previewItem.id)) && (
              <Button
                type="button"
                variant="outline"
                className="w-full justify-start"
                onClick={() => void copySecretFromRow(previewItem, getItemUsername(previewItem), 'Username')}
              >
                <Copy className="mr-2 h-4 w-4" />
                {t('vault.actions.copyUsername')}
              </Button>
            )}
            {previewItem.decryptedData?.password && (opLogVerifiedItemIds === null || opLogVerifiedItemIds.has(previewItem.id)) && (
              <Button
                type="button"
                variant="outline"
                className="w-full justify-start"
                onClick={() => void copySecretFromRow(previewItem, previewItem.decryptedData?.password, 'Password')}
              >
                <KeyRound className="mr-2 h-4 w-4" />
                {t('vault.actions.copyPassword')}
              </Button>
            )}
            <Button type="button" variant="outline" className="w-full justify-start" onClick={() => void toggleItemFavorite(previewItem)}>
              <Star className={cn('mr-2 h-4 w-4 text-amber-400', isItemFavorite(previewItem) && 'fill-current')} />
              {isItemFavorite(previewItem)
                ? t('vault.actions.removeFavorite', { defaultValue: 'Favorit entfernen' })
                : t('vault.actions.addFavorite', { defaultValue: 'Als Favorit markieren' })}
            </Button>
            <Button type="button" variant="outline" className="w-full justify-start" onClick={() => editItemFromPreview(previewItem.id)}>
              <Edit className="mr-2 h-4 w-4" />
              {t('vault.actions.editEntry', { defaultValue: 'Eintrag bearbeiten' })}
            </Button>
            <Button type="button" variant="ghost" className="w-full justify-start text-destructive hover:text-destructive" onClick={() => setDeletePreviewItemId(previewItem.id)}>
              <Trash2 className="mr-2 h-4 w-4" />
              {t('vault.actions.deleteEntry', { defaultValue: 'Eintrag löschen' })}
            </Button>
          </div>

          <div className="mt-5 rounded-2xl border border-border/25 bg-white/[0.012] p-3">
            <details>
              <summary className="cursor-pointer list-none text-sm font-medium text-foreground">
                {t('authenticator.details', { defaultValue: 'Details anzeigen' })}
              </summary>
              <dl className="mt-3 space-y-2 text-xs text-muted-foreground">
                <div className="flex justify-between gap-3">
                  <dt>{t('common.created', { defaultValue: 'Erstellt' })}</dt>
                  <dd className="text-right">{formatVaultItemMetaDate(previewItem.created_at)}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt>{t('common.updated', { defaultValue: 'Geändert' })}</dt>
                  <dd className="text-right">{formatVaultItemMetaDate(previewItem.updated_at)}</dd>
                </div>
              </dl>
            </details>
          </div>
        </VaultItemPreviewPanel>
      )}

      <AlertDialog
        open={!!deletePreviewItem}
        onOpenChange={(open) => {
          if (!open) {
            setDeletePreviewItemId(null);
          }
        }}
      >
        <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('vault.confirmDeleteTitle', { defaultValue: 'Eintrag löschen?' })}
            </AlertDialogTitle>
            <AlertDialogDescription className="leading-relaxed">
              {t('vault.confirmDeleteDescription', {
                defaultValue: 'Dieser Eintrag wird aus dem Tresor entfernt. Diese Aktion kann nicht direkt rückgängig gemacht werden.',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deletingPreviewItem}>
              {t('common.cancel', { defaultValue: 'Abbrechen' })}
            </AlertDialogCancel>
            <AlertDialogAction
              disabled={deletingPreviewItem}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={(event) => {
                event.preventDefault();
                void confirmDeletePreviewItem();
              }}
            >
              {deletingPreviewItem && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {t('common.delete', { defaultValue: 'Löschen' })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={bulkRestoreConfirmOpen}
        onOpenChange={setBulkRestoreConfirmOpen}
      >
        <AlertDialogContent className="w-[calc(100vw-2rem)] max-w-xl">
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t('vault.integrity.confirmBulkRestoreTitle', {
                defaultValue: '{{count}} Einträge wiederherstellen?',
                count: restorablePanelItems.length,
              })}
            </AlertDialogTitle>
            <AlertDialogDescription className="leading-relaxed">
              {t('vault.integrity.confirmBulkRestoreDescription', {
                defaultValue: 'Es werden nur Einträge wiederhergestellt, für die auf diesem Gerät eine vertrauenswürdige lokale Kopie verfügbar ist. Jeder Eintrag wird einzeln geprüft und danach verifiziert.',
              })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>
              {t('common.cancel', {
                defaultValue: 'Abbrechen',
              })}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => {
                event.preventDefault();
                void handleRestoreAllVisible();
              }}
            >
              {t('vault.integrity.confirmBulkRestoreAction', {
                defaultValue: 'Wiederherstellen',
              })}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <VaultQuarantineRestoreProgressDialog
        open={bulkRestoreProgress.open}
        status={bulkRestoreProgress.status}
        total={bulkRestoreProgress.total}
        completed={bulkRestoreProgress.completed}
        failed={bulkRestoreProgress.failed}
        currentItemId={bulkRestoreProgress.currentItemId}
        lastError={bulkRestoreProgress.lastError}
        onContinue={() => {
          setBulkRestoreProgress((current) => ({
            ...current,
            open: false,
          }));
        }}
      />
    </div>
  );
}
