// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Subscription Settings Panel
 *
 * Shows current plan details, billing portal link, and
 * prominent cancellation button (§312k BGB compliant).
 */

import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
    Crown,
    Users,
    Shield,
    ExternalLink,
    Loader2,
    AlertTriangle,
    CreditCard,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { useSubscription } from '@/contexts/SubscriptionContext';
import { cancelSubscription, createPortalSession } from '@/services/subscriptionService';

export function SubscriptionSettings() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { tier, status, cancelAtPeriodEnd, currentPeriodEnd, refresh, loading } = useSubscription();
    const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
    const [cancelling, setCancelling] = useState(false);
    const [cancelError, setCancelError] = useState<string | null>(null);
    const [portalLoading, setPortalLoading] = useState(false);

    const handlePortal = useCallback(async () => {
        setPortalLoading(true);
        try {
            const result = await createPortalSession();
            if (result.url) {
                window.location.href = result.url;
            }
        } catch (err) {
            console.error('Portal error:', err);
        } finally {
            setPortalLoading(false);
        }
    }, []);

    const handleCancel = useCallback(async () => {
        setCancelling(true);
        setCancelError(null);
        try {
            const result = await cancelSubscription();
            if (result.success) {
                setCancelDialogOpen(false);
                await refresh();
            } else {
                setCancelError(result.error || t('subscription.cancel_error'));
            }
        } catch {
            setCancelError(t('subscription.cancel_error'));
        } finally {
            setCancelling(false);
        }
    }, [refresh, t]);

    

    const tierIcon = {
        free: <Shield className="w-5 h-5 text-primary" />,
        premium: <Crown className="w-5 h-5 text-yellow-500" />,
        families: <Users className="w-5 h-5 text-blue-500" />,
    }[tier];

    const tierLabel = tier.toUpperCase();

    const formattedEnd = currentPeriodEnd
        ? new Date(currentPeriodEnd).toLocaleDateString('de-DE', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
        })
        : null;

    return (
        <div className="space-y-4">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                {t('subscription.settings_title')}
            </h3>

            {/* Current Plan Info */}
            <div className="rounded-xl border bg-card p-4 space-y-3">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        {tierIcon}
                        <span className="font-semibold">{tierLabel}</span>
                        {cancelAtPeriodEnd && (
                            <span className="text-xs bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 px-2 py-0.5 rounded-full">
                                {t('subscription.cancelling')}
                            </span>
                        )}
                    </div>
                    <span className="text-sm text-muted-foreground capitalize">
                        {status === 'active' && !cancelAtPeriodEnd && t('subscription.status_active')}
                        {status === 'active' && cancelAtPeriodEnd && t('subscription.status_cancelling')}
                        {status === 'canceled' && t('subscription.status_canceled')}
                        {status === 'past_due' && t('subscription.status_past_due')}
                    </span>
                </div>

                {formattedEnd && tier !== 'free' && (
                    <p className="text-sm text-muted-foreground">
                        {cancelAtPeriodEnd
                            ? t('subscription.access_until', { date: formattedEnd })
                            : t('subscription.renews_on', { date: formattedEnd })}
                    </p>
                )}
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap gap-2">
                {tier === 'free' && (
                    <Button
                        onClick={() => navigate('/pricing')}
                        className="flex items-center gap-2"
                    >
                        <Crown className="w-4 h-4" />
                        {t('subscription.upgrade_now')}
                    </Button>
                )}

                {tier !== 'free' && (
                    <Button
                        variant="outline"
                        onClick={handlePortal}
                        disabled={portalLoading}
                        className="flex items-center gap-2"
                    >
                        {portalLoading ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                            <CreditCard className="w-4 h-4" />
                        )}
                        {t('subscription.manage_billing')}
                        <ExternalLink className="w-3 h-3" />
                    </Button>
                )}

                {/* §312k BGB: Prominent cancellation button */}
                {tier !== 'free' && !cancelAtPeriodEnd && (
                    <Button
                        variant="destructive"
                        onClick={() => setCancelDialogOpen(true)}
                        className="flex items-center gap-2"
                    >
                        {t('subscription.cancel_now')}
                    </Button>
                )}
            </div>

            {/* Cancel Confirmation Dialog (2-step process) */}
            <Dialog open={cancelDialogOpen} onOpenChange={setCancelDialogOpen}>
                <DialogContent className="sm:max-w-md">
                    <DialogHeader>
                        <DialogTitle className="flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-destructive" />
                            {t('subscription.cancel_title')}
                        </DialogTitle>
                        <DialogDescription>
                            {t('subscription.cancel_description', {
                                tier: tierLabel,
                                date: formattedEnd,
                            })}
                        </DialogDescription>
                    </DialogHeader>

                    <div className="py-4 space-y-3">
                        <p className="text-sm text-muted-foreground">
                            {t('subscription.cancel_effects')}
                        </p>
                        <ul className="text-sm text-muted-foreground space-y-1.5 ml-4 list-disc">
                            <li>{t('subscription.cancel_effect_access')}</li>
                            <li>{t('subscription.cancel_effect_features')}</li>
                            <li>{t('subscription.cancel_effect_data')}</li>
                        </ul>
                    </div>

                    {cancelError && (
                        <div className="text-sm text-destructive p-3 rounded-lg bg-destructive/10">
                            {cancelError}
                        </div>
                    )}

                    <DialogFooter className="flex gap-2">
                        <Button variant="outline" onClick={() => setCancelDialogOpen(false)} disabled={cancelling}>
                            {t('subscription.keep_plan')}
                        </Button>
                        <Button variant="destructive" onClick={handleCancel} disabled={cancelling}>
                            {cancelling ? (
                                <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                                t('subscription.confirm_cancel')
                            )}
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}
