// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Checkout Dialog with Widerruf Consent
 *
 * German law (EU consumer protection) requires explicit consent
 * before starting a digital subscription:
 * 1. User must request early execution before cooling-off period ends
 * 2. User must acknowledge loss of withdrawal right
 *
 * Both checkboxes are MANDATORY before checkout can proceed.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Loader2, AlertTriangle } from 'lucide-react';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { createCheckoutSession } from '@/services/subscriptionService';
import { useSubscription } from '@/contexts/SubscriptionContext';
import { PLAN_CONFIG, type PlanKey } from '@/config/planConfig';

interface CheckoutDialogProps {
    planKey: PlanKey;
    open: boolean;
    onClose: () => void;
}

export function CheckoutDialog({ planKey, open, onClose }: CheckoutDialogProps) {
    const { t } = useTranslation();
    const { hasUsedIntroDiscount } = useSubscription();
    const [consentExecution, setConsentExecution] = useState(false);
    const [consentLoss, setConsentLoss] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const planInfo = PLAN_CONFIG[planKey];
    const showDiscount = !hasUsedIntroDiscount && planKey.endsWith('_monthly');

    const canProceed = consentExecution && consentLoss;

    const handleCheckout = async () => {
        if (!canProceed) return;

        setLoading(true);
        setError(null);

        try {
            const result = await createCheckoutSession(planKey, {
                execution: consentExecution,
                loss: consentLoss,
            });

            if (result.error) {
                setError(result.error);
                return;
            }

            if (result.url) {
                window.location.href = result.url;
            }
        } catch (err) {
            setError(t('subscription.checkout_error'));
        } finally {
            setLoading(false);
        }
    };

    const formatPrice = (cents: number) => {
        return (cents / 100).toFixed(2).replace('.', ',');
    };

    return (
        <Dialog open={open} onOpenChange={() => !loading && onClose()}>
            <DialogContent className="sm:max-w-lg">
                <DialogHeader>
                    <DialogTitle>{t('subscription.checkout_title')}</DialogTitle>
                    <DialogDescription>
                        {t('subscription.checkout_description', { plan: planInfo.label })}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-6 py-4">
                    {/* Price Summary */}
                    <div className="rounded-lg bg-muted/50 p-4 space-y-2">
                        <div className="flex justify-between text-sm">
                            <span>{planInfo.label}</span>
                            <span className="font-semibold">
                                €{formatPrice(planInfo.amount)}/{planKey.endsWith('_monthly') ? t('subscription.month') : t('subscription.year')}
                            </span>
                        </div>
                        {showDiscount && (
                            <div className="flex justify-between text-sm text-green-600 dark:text-green-400">
                                <span>{t('subscription.first_month_discount')}</span>
                                <span className="font-semibold">-50%</span>
                            </div>
                        )}
                    </div>

                    {/* Widerruf Consent Checkboxes (§355 BGB / EU Consumer Rights Directive) */}
                    <div className="space-y-4">
                        <div className="flex items-start gap-3 p-3 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-950/20">
                            <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
                            <p className="text-xs text-muted-foreground">
                                {t('subscription.widerruf_info')}
                            </p>
                        </div>

                        <div className="flex items-start gap-3">
                            <Checkbox
                                id="consent-execution"
                                checked={consentExecution}
                                onCheckedChange={(checked) => setConsentExecution(checked === true)}
                                disabled={loading}
                            />
                            <Label
                                htmlFor="consent-execution"
                                className="text-sm leading-relaxed cursor-pointer"
                            >
                                {t('subscription.widerruf_consent_execution')}
                            </Label>
                        </div>

                        <div className="flex items-start gap-3">
                            <Checkbox
                                id="consent-loss"
                                checked={consentLoss}
                                onCheckedChange={(checked) => setConsentLoss(checked === true)}
                                disabled={loading}
                            />
                            <Label
                                htmlFor="consent-loss"
                                className="text-sm leading-relaxed cursor-pointer"
                            >
                                {t('subscription.widerruf_consent_loss')}
                            </Label>
                        </div>
                    </div>

                    {error && (
                        <div className="text-sm text-destructive p-3 rounded-lg bg-destructive/10">
                            {error}
                        </div>
                    )}
                </div>

                <DialogFooter className="flex gap-2">
                    <Button variant="outline" onClick={onClose} disabled={loading}>
                        {t('subscription.cancel')}
                    </Button>
                    <Button
                        onClick={handleCheckout}
                        disabled={!canProceed || loading}
                        className="min-w-[140px]"
                    >
                        {loading ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                            t('subscription.proceed_checkout')
                        )}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
