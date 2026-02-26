// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Admin Subscription Assigner
 *
 * Internal admin utility to assign a subscription tier to a user.
 */

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { assignUserSubscription, type SubscriptionTier } from '@/services/adminService';

interface AdminSubscriptionAssignerProps {
    ticketId?: string;
    defaultUserId?: string;
}

interface ResolvedUser {
    id: string;
}

// self_hosted intentionally excluded until client feature
// matrix and subscription typing fully support it
const TIER_OPTIONS: SubscriptionTier[] = ['free', 'premium', 'families'];

/**
 * Renders a manual subscription assignment panel for admins.
 *
 * @param props - Component props
 * @returns Subscription assignment panel
 */
export function AdminSubscriptionAssigner({ ticketId, defaultUserId }: AdminSubscriptionAssignerProps) {
    const { t } = useTranslation();
    const { toast } = useToast();

    const [lookupInput, setLookupInput] = useState('');
    const [resolvedUser, setResolvedUser] = useState<ResolvedUser | null>(null);
    const [selectedTier, setSelectedTier] = useState<SubscriptionTier>('free');
    const [reason, setReason] = useState('');
    const [isAssigning, setIsAssigning] = useState(false);
    const [errorKey, setErrorKey] = useState<string | null>(null);
    const assignRequestRef = useRef<string | null>(null);

    useEffect(() => {
        // Reset on both user AND ticket change to prevent cross-ticket leakage
        assignRequestRef.current = null;
        setLookupInput(defaultUserId || '');
        setResolvedUser(null);
        setSelectedTier('free');
        setReason('');
        setErrorKey(null);
    }, [defaultUserId, ticketId]);

    const handleResolveUser = () => {
        const candidate = lookupInput.trim();
        if (!candidate) {
            setResolvedUser(null);
            setErrorKey('admin.support.subscriptionAssigner.errorMissingUser');
            return;
        }

        setResolvedUser({ id: candidate });
        setErrorKey(null);
    };

    const handleAssign = async () => {
        const requestToken = crypto.randomUUID();
        assignRequestRef.current = requestToken;
        const normalizedReason = reason.trim();
        // SECURITY: Only use explicitly resolved user, never fall back
        // to defaultUserId directly to prevent silent wrong-user assignment
        if (!resolvedUser?.id) {
            setErrorKey('admin.support.subscriptionAssigner.errorMissingUser');
            return;
        }
        const normalizedTargetUserId = resolvedUser.id.trim();

        if (normalizedReason.length < 3) {
            setErrorKey('admin.support.subscriptionAssigner.errorReasonTooShort');
            return;
        }

        setIsAssigning(true);
        setErrorKey(null);

        const { success, error } = await assignUserSubscription({
            userId: normalizedTargetUserId,
            tier: selectedTier,
            reason: normalizedReason,
            ticketId,
        });

        setIsAssigning(false);

        // Guard: use request token instead of ticketId comparison
        // because ticketId is frozen in closure and cannot detect switches
        if (assignRequestRef.current !== requestToken) {
            return;
        }

        if (!success || error) {
            setErrorKey('admin.support.subscriptionAssigner.errorAssignFailed');
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.support.subscriptionAssigner.errorAssignFailed'),
            });
            return;
        }

        setReason('');
        setErrorKey(null);
        setResolvedUser({ id: normalizedTargetUserId });

        toast({
            title: t('common.success'),
            description: t('admin.support.subscriptionAssigner.success'),
        });
    };

    return (
        <Card>
            <CardHeader>
                <CardTitle>{t('admin.support.subscriptionAssigner.title')}</CardTitle>
                <CardDescription>{t('admin.support.subscriptionAssigner.description')}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
                <div className="space-y-2">
                    <Label htmlFor="admin-subscription-user-lookup">
                        {t('admin.support.subscriptionAssigner.lookupLabel')}
                    </Label>
                    <div className="flex items-center gap-2">
                        <Input
                            id="admin-subscription-user-lookup"
                            value={lookupInput}
                            onChange={(event) => {
                                setLookupInput(event.target.value);
                                setResolvedUser(null);
                            }}
                            onKeyDown={(event) => {
                                if (event.key === 'Enter') {
                                    event.preventDefault();
                                    handleResolveUser();
                                }
                            }}
                            placeholder={t('admin.support.subscriptionAssigner.lookupPlaceholder')}
                        />
                        <Button type="button" variant="outline" onClick={handleResolveUser}>
                            {t('admin.support.subscriptionAssigner.resolveAction')}
                        </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                        {defaultUserId
                            ? t('admin.support.subscriptionAssigner.ticketUserHint', { userId: defaultUserId })
                            : t('admin.support.subscriptionAssigner.noTicketUserHint')}
                    </p>
                    {resolvedUser?.id && (
                        <p className="text-xs text-muted-foreground">
                            {t('admin.support.subscriptionAssigner.targetUser', { userId: resolvedUser.id })}
                        </p>
                    )}
                </div>

                <div className="space-y-2">
                    <Label htmlFor="admin-subscription-tier">{t('admin.support.subscriptionAssigner.tierLabel')}</Label>
                    <Select value={selectedTier} onValueChange={(value) => setSelectedTier(value as SubscriptionTier)}>
                        <SelectTrigger id="admin-subscription-tier" className="w-full sm:w-[260px]">
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            {TIER_OPTIONS.map((tier) => (
                                <SelectItem key={tier} value={tier}>
                                    {t(`admin.support.subscriptionAssigner.tier.${tier}`)}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>

                <div className="space-y-2">
                    <Label htmlFor="admin-subscription-reason">{t('admin.support.subscriptionAssigner.reasonLabel')}</Label>
                    <Textarea
                        id="admin-subscription-reason"
                        value={reason}
                        onChange={(event) => setReason(event.target.value)}
                        rows={3}
                        maxLength={500}
                        placeholder={t('admin.support.subscriptionAssigner.reasonPlaceholder')}
                    />
                </div>

                {errorKey && <p className="text-sm text-destructive">{t(errorKey)}</p>}

                <Button onClick={handleAssign} disabled={isAssigning || !resolvedUser}>
                    {isAssigning
                        ? t('admin.support.subscriptionAssigner.assigning')
                        : t('admin.support.subscriptionAssigner.assignAction')}
                </Button>
            </CardContent>
        </Card>
    );
}
