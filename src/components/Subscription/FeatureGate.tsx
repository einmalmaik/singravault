// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Feature Gate Component
 *
 * Wrapper component that shows an upgrade prompt when the user
 * lacks the required subscription tier for a feature.
 */

import { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Lock, Crown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useFeatureGate } from '@/hooks/useFeatureGate';
import type { FeatureName } from '@/config/planConfig';

interface FeatureGateProps {
    /** The feature to check access for */
    feature: FeatureName;
    /** Content to render when access is granted */
    children: ReactNode;
    /** Optional: show a compact inline lock icon instead of the full prompt */
    compact?: boolean;
    /** Optional: custom label for the feature (otherwise uses i18n key) */
    featureLabel?: string;
}

/**
 * Wraps content behind a feature gate.
 * Shows upgrade CTA if the user doesn't have the required tier.
 *
 * @example
 * <FeatureGate feature="file_attachments">
 *   <FileAttachmentsPanel />
 * </FeatureGate>
 */
export function FeatureGate({ feature, children, compact, featureLabel }: FeatureGateProps) {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { allowed, requiredTier } = useFeatureGate(feature);

    // If feature is allowed, render children
    if (allowed) {
        return <>{children}</>;
    }

    if (compact) {
        return (
            <div className="flex items-center gap-2 text-muted-foreground opacity-60 cursor-not-allowed">
                <Lock className="w-4 h-4" />
                <span className="text-sm">{featureLabel || t(`subscription.features.${feature}`)}</span>
                <span className="text-xs bg-primary/10 text-primary px-2 py-0.5 rounded-full font-medium uppercase">
                    {requiredTier}
                </span>
            </div>
        );
    }

    return (
        <div className="rounded-xl border border-dashed border-primary/30 bg-primary/5 p-6 text-center space-y-3">
            <div className="flex justify-center">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                    <Crown className="w-6 h-6 text-primary" />
                </div>
            </div>
            <h4 className="font-semibold text-sm">
                {t('subscription.feature_locked_title')}
            </h4>
            <p className="text-sm text-muted-foreground max-w-sm mx-auto">
                {t('subscription.feature_locked_description', {
                    feature: featureLabel || t(`subscription.features.${feature}`),
                    tier: requiredTier.toUpperCase(),
                })}
            </p>
            <Button size="sm" onClick={() => navigate('/pricing')}>
                {t('subscription.upgrade_now')}
            </Button>
        </div>
    );
}
