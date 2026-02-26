// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Support Settings Component
 *
 * Provides in-app support ticket creation, SLA visibility, recent ticket history,
 * and optional response metrics for support team members.
 */

import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
    BarChart3,
    Clock3,
    LifeBuoy,
    Loader2,
    MessageSquare,
    Send,
    ShieldAlert,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

import {
    getSupportResponseMetrics,
    listSupportTickets,
    submitSupportTicket,
    type CreateSupportTicketInput,
    type SupportEntitlement,
    type SupportResponseMetric,
    type SupportTicketSummary,
} from '@/services/supportService';
import { useToast } from '@/hooks/use-toast';

const CATEGORY_OPTIONS: Array<CreateSupportTicketInput['category']> = [
    'general',
    'technical',
    'billing',
    'security',
    'family',
    'other',
];

/**
 * Renders support ticket creation and status overview.
 *
 * @returns Settings card with support form and SLA information
 */
export function SupportSettings() {
    const { t, i18n } = useTranslation();
    const { toast } = useToast();

    const [subject, setSubject] = useState('');
    const [category, setCategory] = useState<CreateSupportTicketInput['category']>('general');
    const [message, setMessage] = useState('');

    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isLoading, setIsLoading] = useState(true);

    const [entitlement, setEntitlement] = useState<SupportEntitlement | null>(null);
    const [tickets, setTickets] = useState<SupportTicketSummary[]>([]);
    const [metrics, setMetrics] = useState<SupportResponseMetric[]>([]);

    const [loadError, setLoadError] = useState<string | null>(null);

    const currentSlaText = useMemo(() => {
        const slaHours = entitlement?.sla_hours ?? 72;
        if (slaHours <= 24) {
            return t('settings.support.sla.priority24h');
        }
        return t('settings.support.sla.standard72h');
    }, [entitlement?.sla_hours, t]);

    const isPriority = entitlement?.is_priority ?? false;

    const loadSupportData = async () => {
        setIsLoading(true);
        setLoadError(null);

        const [listResult, metricsResult] = await Promise.all([
            listSupportTickets(),
            getSupportResponseMetrics(30),
        ]);

        if (listResult.error) {
            setLoadError(listResult.error.message);
        } else {
            setEntitlement(listResult.entitlement);
            setTickets(listResult.tickets);
        }

        // Metrics may return permission errors for non-admin users.
        // We silently ignore those and only render metrics when data exists.
        if (!metricsResult.error && metricsResult.metrics.length > 0) {
            setMetrics(metricsResult.metrics);
        } else {
            setMetrics([]);
        }

        setIsLoading(false);
    };

    useEffect(() => {
        void loadSupportData();
    }, []);

    const handleSubmit = async () => {
        if (subject.trim().length < 3 || message.trim().length < 10) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.support.validation'),
            });
            return;
        }

        setIsSubmitting(true);
        const { error } = await submitSupportTicket({
            subject: subject.trim(),
            category,
            message: message.trim(),
        });
        setIsSubmitting(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.support.submitError'),
            });
            return;
        }

        setSubject('');
        setMessage('');
        setCategory('general');

        toast({
            title: t('common.success'),
            description: t('settings.support.submitSuccess'),
        });

        await loadSupportData();
    };

    const formatDate = (isoDate: string) => {
        return new Date(isoDate).toLocaleString(i18n.language === 'de' ? 'de-DE' : 'en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    };

    const getStatusLabel = (status: SupportTicketSummary['status']) => {
        return t(`settings.support.status.${status}`);
    };

    const getStatusVariant = (status: SupportTicketSummary['status']) => {
        if (status === 'resolved' || status === 'closed') {
            return 'secondary' as const;
        }
        if (status === 'in_progress') {
            return 'default' as const;
        }
        return 'outline' as const;
    };

    const aggregateMetric = metrics.find((metric) => metric.segment === 'all') || null;

    return (
        <Card>
            <CardHeader>
                <CardTitle className="flex items-center gap-2">
                    <LifeBuoy className="w-5 h-5" />
                    {t('settings.support.title')}
                </CardTitle>
                <CardDescription>{t('settings.support.description')}</CardDescription>
            </CardHeader>

            <CardContent className="space-y-6">
                <div className="rounded-lg border bg-muted/30 p-4 space-y-2">
                    <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 text-sm font-medium">
                            <Clock3 className="w-4 h-4" />
                            {t('settings.support.currentSla')}
                        </div>
                        <Badge variant={isPriority ? 'default' : 'secondary'}>{currentSlaText}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{t('settings.support.slaDisclaimer')}</p>
                </div>

                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
                    <div className="flex items-start gap-2">
                        <ShieldAlert className="w-4 h-4 mt-0.5 text-amber-600" />
                        <p>{t('settings.support.securityHint')}</p>
                    </div>
                </div>

                <div className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="support-subject">{t('settings.support.subject')}</Label>
                        <Input
                            id="support-subject"
                            value={subject}
                            onChange={(e) => setSubject(e.target.value)}
                            maxLength={160}
                            placeholder={t('settings.support.subjectPlaceholder')}
                        />
                    </div>

                    <div className="space-y-2">
                        <Label>{t('settings.support.category')}</Label>
                        <Select value={category} onValueChange={(value) => setCategory(value as CreateSupportTicketInput['category'])}>
                            <SelectTrigger className="w-full sm:w-[280px]">
                                <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                                {CATEGORY_OPTIONS.map((option) => (
                                    <SelectItem key={option} value={option}>
                                        {t(`settings.support.categories.${option}`)}
                                    </SelectItem>
                                ))}
                            </SelectContent>
                        </Select>
                    </div>

                    <div className="space-y-2">
                        <Label htmlFor="support-message">{t('settings.support.message')}</Label>
                        <Textarea
                            id="support-message"
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            minLength={10}
                            maxLength={5000}
                            rows={6}
                            placeholder={t('settings.support.messagePlaceholder')}
                        />
                    </div>

                    <Button onClick={handleSubmit} disabled={isSubmitting} className="flex items-center gap-2">
                        {isSubmitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                        {isSubmitting ? t('settings.support.submitting') : t('settings.support.submit')}
                    </Button>
                </div>

                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-muted-foreground">
                        <MessageSquare className="w-4 h-4" />
                        {t('settings.support.recentTickets')}
                    </div>

                    {isLoading && (
                        <div className="text-sm text-muted-foreground flex items-center gap-2">
                            <Loader2 className="w-4 h-4 animate-spin" />
                            {t('common.loading')}
                        </div>
                    )}

                    {!isLoading && loadError && (
                        <div className="text-sm text-destructive">{loadError}</div>
                    )}

                    {!isLoading && !loadError && tickets.length === 0 && (
                        <p className="text-sm text-muted-foreground">{t('settings.support.noTickets')}</p>
                    )}

                    {!isLoading && tickets.length > 0 && (
                        <div className="space-y-3">
                            {tickets.map((ticket) => (
                                <div key={ticket.id} className="rounded-lg border p-3 space-y-2">
                                    <div className="flex items-center justify-between gap-2">
                                        <p className="font-medium text-sm truncate">{ticket.subject}</p>
                                        <Badge variant={getStatusVariant(ticket.status)}>{getStatusLabel(ticket.status)}</Badge>
                                    </div>

                                    <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                                        <span>{t(`settings.support.categories.${ticket.category}`)}</span>
                                        <span>•</span>
                                        <span>{formatDate(ticket.created_at)}</span>
                                        <span>•</span>
                                        <span>
                                            {ticket.first_response_minutes !== null
                                                ? t('settings.support.firstResponseTime', { minutes: ticket.first_response_minutes })
                                                : t('settings.support.awaitingFirstResponse')}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {aggregateMetric && (
                    <div className="rounded-lg border bg-muted/30 p-4 space-y-2">
                        <div className="flex items-center gap-2 text-sm font-medium">
                            <BarChart3 className="w-4 h-4" />
                            {t('settings.support.metricsTitle')}
                        </div>
                        <p className="text-sm">
                            {t('settings.support.averageResponse30d', {
                                hours: aggregateMetric.avg_first_response_hours.toFixed(2),
                            })}
                        </p>
                        <p className="text-xs text-muted-foreground">
                            {t('settings.support.metricsFootnote', {
                                hitRate: aggregateMetric.sla_hit_rate_percent.toFixed(2),
                            })}
                        </p>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
