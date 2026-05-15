// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Vault Sidebar Health Summary Hook
 *
 * Lazily computes the password health summary the sidebar's status card uses.
 *
 * Disabled (and clears any prior summary) when:
 *  - vault health reports are gated off for this user
 *  - no user is authenticated
 *  - the integrity result is `blocked` or `quarantine` — the sidebar already
 *    surfaces the more urgent integrity signal in those cases
 *  - the premium hook is not registered (core build)
 *
 * Request id-based cancellation prevents an older in-flight analysis from
 * overwriting a newer summary if dependencies change mid-run.
 */

import { useEffect, useRef, useState } from 'react';

import type { VaultHealthSidebarSummary, ServiceHooks } from '@/extensions/types';
import { getServiceHooks } from '@/extensions/registry';
import { buildVaultHealthSidebarSummaryInput } from '@/services/vaultHealthAnalysisItemsService';

interface IntegrityResultShape {
  readonly mode?: string;
  readonly quarantinedItems?: { readonly id: string }[];
}

type GetVaultHealthAnalysisItems = () => Promise<Parameters<typeof buildVaultHealthSidebarSummaryInput>[0]>;

export interface UseVaultSidebarHealthInput {
  readonly enabled: boolean;
  readonly userId: string | null;
  readonly lastIntegrityResult: IntegrityResultShape | null;
  readonly vaultDataVersion: number;
  readonly getVaultHealthAnalysisItems: GetVaultHealthAnalysisItems;
}

export interface UseVaultSidebarHealthResult {
  readonly summary: VaultHealthSidebarSummary | null;
  readonly loading: boolean;
}

export function useVaultSidebarHealth({
  enabled,
  userId,
  lastIntegrityResult,
  vaultDataVersion,
  getVaultHealthAnalysisItems,
}: UseVaultSidebarHealthInput): UseVaultSidebarHealthResult {
  const [summary, setSummary] = useState<VaultHealthSidebarSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const requestIdRef = useRef(0);

  useEffect(() => {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;

    if (!enabled || !userId) {
      setSummary(null);
      setLoading(false);
      return;
    }

    if (lastIntegrityResult?.mode === 'blocked' || lastIntegrityResult?.mode === 'quarantine') {
      setSummary(null);
      setLoading(false);
      return;
    }

    const hooks: ServiceHooks = getServiceHooks();
    const analyzeVaultHealthSummary = hooks.analyzeVaultHealthSummary;
    if (!analyzeVaultHealthSummary) {
      setSummary(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    void (async () => {
      try {
        const healthItems = await getVaultHealthAnalysisItems();
        const summaryInput = await buildVaultHealthSidebarSummaryInput(healthItems);
        if (requestIdRef.current === requestId) {
          setSummary(analyzeVaultHealthSummary(summaryInput));
        }
      } catch {
        if (requestIdRef.current === requestId) {
          setSummary(null);
        }
        console.error('Vault health sidebar analysis failed.');
      } finally {
        if (requestIdRef.current === requestId) {
          setLoading(false);
        }
      }
    })();
  }, [
    enabled,
    getVaultHealthAnalysisItems,
    lastIntegrityResult?.mode,
    lastIntegrityResult?.quarantinedItems?.length,
    userId,
    vaultDataVersion,
  ]);

  return { summary, loading };
}
