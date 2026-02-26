// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Admin Support Panel
 *
 * Internal support inbox for moderators/admins.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { BarChart3, Clock3, Loader2, MessageSquare, RefreshCcw, Send } from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';

import { useToast } from '@/hooks/use-toast';
import {
    type AdminSupportMetric,
    type AdminSupportTicket,
    type AdminSupportTicketDetail,
    type AdminSupportTicketStatus,
    getAdminSupportTicket,
    listAdminSupportMetrics,
    listAdminSupportTickets,
    replyToAdminSupportTicket,
    updateAdminSupportTicketStatus,
} from '@/services/adminService';

const STATUS_OPTIONS: AdminSupportTicketStatus[] = [
    'open',
    'in_progress',
    'waiting_user',
    'resolved',
    'closed',
];

interface AdminSupportPanelProps {
    permissions: string[];
}

/**
 * Internal support inbox panel with ticket detail and reply actions.
 *
 * @param props - Component props
 * @returns Support inbox panel
 */
export function AdminSupportPanel({ permissions }: AdminSupportPanelProps) {
    const { t, i18n } = useTranslation();
    const { toast } = useToast();

    const canReadTickets = permissions.includes('support.tickets.read');
    const canReply = permissions.includes('support.tickets.reply');
    const canReadInternal = permissions.includes('support.tickets.reply_internal');
    const canUpdateStatus = permissions.includes('support.tickets.status');
    const canReadMetrics = permissions.includes('support.metrics.read');


    const [tickets, setTickets] = useState<AdminSupportTicket[]>([]);
    const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
    const [selectedTicket, setSelectedTicket] = useState<AdminSupportTicketDetail | null>(null);
    const [metrics, setMetrics] = useState<AdminSupportMetric[]>([]);

    const [statusFilter, setStatusFilter] = useState<'all' | AdminSupportTicketStatus>('all');
    const [searchDraft, setSearchDraft] = useState('');
    const [searchQuery, setSearchQuery] = useState('');

    const [replyMessage, setReplyMessage] = useState('');
    const [replyInternal, setReplyInternal] = useState(false);
    const [statusUpdate, setStatusUpdate] = useState<AdminSupportTicketStatus>('open');

    const [isLoadingTickets, setIsLoadingTickets] = useState(false);
    const [isLoadingTicket, setIsLoadingTicket] = useState(false);
    const [isLoadingMetrics, setIsLoadingMetrics] = useState(false);
    const [isReplying, setIsReplying] = useState(false);
    const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
    const selectedTicketIdRef = useRef<string | null>(null);

    const aggregateMetric = useMemo(() => {
        return metrics.find((metric) => metric.segment === 'all') || null;
    }, [metrics]);

    const formatDate = useCallback(
        (isoDate: string) => {
            return new Date(isoDate).toLocaleString(i18n.language === 'de' ? 'de-DE' : 'en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        },
        [i18n.language],
    );

    const getStatusVariant = useCallback((status: AdminSupportTicketStatus) => {
        if (status === 'resolved' || status === 'closed') {
            return 'secondary' as const;
        }
        if (status === 'in_progress') {
            return 'default' as const;
        }
        return 'outline' as const;
    }, []);

    const loadTickets = useCallback(async () => {
        if (!canReadTickets) {
            setTickets([]);
            setSelectedTicketId(null);
            return;
        }

        setIsLoadingTickets(true);
        const { tickets: rows, error } = await listAdminSupportTickets({
            status: statusFilter === 'all' ? undefined : statusFilter,
            search: searchQuery || undefined,
            limit: 50,
        });
        setIsLoadingTickets(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.support.loadError'),
            });
            return;
        }

        setTickets(rows);

        if (rows.length === 0) {
            setSelectedTicketId(null);
            return;
        }

        if (!selectedTicketId || !rows.some((ticket) => ticket.id === selectedTicketId)) {
            setSelectedTicketId(rows[0].id);
        }
    }, [canReadTickets, searchQuery, selectedTicketId, statusFilter, t, toast]);

    const loadTicketDetail = useCallback(
        async (ticketId: string) => {
            if (!canReadTickets) {
                setSelectedTicket(null);
                return;
            }

            setIsLoadingTicket(true);
            const { detail, error } = await getAdminSupportTicket(ticketId);
            setIsLoadingTicket(false);

            if (error || !detail) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('admin.support.ticketLoadError'),
                });
                return;
            }

            setSelectedTicket(detail);
        },
        [canReadTickets, t, toast],
    );

    const loadMetrics = useCallback(async () => {
        if (!canReadMetrics) {
            setMetrics([]);
            return;
        }

        setIsLoadingMetrics(true);
        const { metrics: rows, error } = await listAdminSupportMetrics(30);
        setIsLoadingMetrics(false);

        if (error) {
            setMetrics([]);
            return;
        }

        setMetrics(rows);
    }, [canReadMetrics]);

    useEffect(() => {
        void loadTickets();
    }, [loadTickets]);

    useEffect(() => {
        selectedTicketIdRef.current = selectedTicketId;
    }, [selectedTicketId]);

    useEffect(() => {
        if (!selectedTicketId) {
            setSelectedTicket(null);
            return;
        }
        void loadTicketDetail(selectedTicketId);
    }, [loadTicketDetail, selectedTicketId]);

    useEffect(() => {
        void loadMetrics();
    }, [loadMetrics]);

    useEffect(() => {
        if (selectedTicket?.ticket.status) {
            setStatusUpdate(selectedTicket.ticket.status);
        }
    }, [selectedTicket?.ticket.status]);

    const applySearch = () => {
        setSearchQuery(searchDraft.trim());
    };

    const handleReply = async () => {
        if (!selectedTicketId || !canReply) {
            return;
        }
        const activeTicketId = selectedTicketId;

        const message = replyMessage.trim();
        if (message.length < 1) {
            return;
        }

        setIsReplying(true);
        const { error } = await replyToAdminSupportTicket({
            ticketId: selectedTicketId,
            message,
            isInternal: replyInternal,
        });
        setIsReplying(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.support.replyError'),
            });
            return;
        }

        setReplyMessage('');
        setReplyInternal(false);

        toast({
            title: t('common.success'),
            description: t('admin.support.replySent'),
        });

        await loadTickets();
        if (activeTicketId === selectedTicketIdRef.current) {
            // Guard: skip refresh if user switched tickets during async mutation
            await loadTicketDetail(activeTicketId);
        }
        await loadMetrics();
    };

    const handleStatusUpdate = async () => {
        if (!selectedTicketId || !canUpdateStatus) {
            return;
        }
        const activeTicketId = selectedTicketId;

        setIsUpdatingStatus(true);
        const { error } = await updateAdminSupportTicketStatus(selectedTicketId, statusUpdate);
        setIsUpdatingStatus(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('admin.support.statusError'),
            });
            return;
        }

        toast({
            title: t('common.success'),
            description: t('admin.support.statusUpdated'),
        });

        await loadTickets();
        if (activeTicketId === selectedTicketIdRef.current) {
            // Guard: skip refresh if user switched tickets during async mutation
            await loadTicketDetail(activeTicketId);
        }
        await loadMetrics();
    };

    if (!canReadTickets) {
        return (
            <Card>
                <CardHeader>
                    <CardTitle>{t('admin.support.title')}</CardTitle>
                    <CardDescription>{t('admin.support.noAccess')}</CardDescription>
                </CardHeader>
            </Card>
        );
    }

    return (
        <div className="space-y-4">
            {canReadMetrics && (
                <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-base">
                            <BarChart3 className="w-4 h-4" />
                            {t('admin.support.metricsTitle')}
                        </CardTitle>
                    </CardHeader>
                    <CardContent>
                        {isLoadingMetrics ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                {t('common.loading')}
                            </div>
                        ) : aggregateMetric ? (
                            <div className="space-y-1 text-sm">
                                <p>
                                    {t('admin.support.metricResponse', {
                                        hours: aggregateMetric.avg_first_response_hours.toFixed(2),
                                    })}
                                </p>
                                <p className="text-muted-foreground">
                                    {t('admin.support.metricHitRate', {
                                        rate: aggregateMetric.sla_hit_rate_percent.toFixed(2),
                                    })}
                                </p>
                            </div>
                        ) : (
                            <p className="text-sm text-muted-foreground">{t('admin.support.noMetrics')}</p>
                        )}
                    </CardContent>
                </Card>
            )}

            <div className="grid gap-4 lg:grid-cols-[minmax(280px,360px)_1fr]">
                <Card>
                    <CardHeader className="space-y-3">
                        <div className="flex items-center justify-between gap-2">
                            <CardTitle className="text-base">{t('admin.support.inboxTitle')}</CardTitle>
                            <Button variant="outline" size="sm" onClick={() => void loadTickets()}>
                                <RefreshCcw className="w-4 h-4 mr-1" />
                                {t('admin.support.refresh')}
                            </Button>
                        </div>
                        <div className="space-y-2">
                            <Label>{t('admin.support.filters.status')}</Label>
                            <Select
                                value={statusFilter}
                                onValueChange={(value) => setStatusFilter(value as 'all' | AdminSupportTicketStatus)}
                            >
                                <SelectTrigger>
                                    <SelectValue />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="all">{t('admin.support.filters.allStatuses')}</SelectItem>
                                    {STATUS_OPTIONS.map((status) => (
                                        <SelectItem key={status} value={status}>
                                            {t(`settings.support.status.${status}`)}
                                        </SelectItem>
                                    ))}
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="flex items-center gap-2">
                            <Input
                                value={searchDraft}
                                onChange={(event) => setSearchDraft(event.target.value)}
                                onKeyDown={(event) => {
                                    if (event.key === 'Enter') {
                                        applySearch();
                                    }
                                }}
                                placeholder={t('admin.support.filters.searchPlaceholder')}
                            />
                            <Button variant="secondary" onClick={applySearch}>
                                {t('admin.support.filters.applySearch')}
                            </Button>
                        </div>
                    </CardHeader>
                    <CardContent>
                        {isLoadingTickets ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                {t('common.loading')}
                            </div>
                        ) : tickets.length === 0 ? (
                            <p className="text-sm text-muted-foreground">{t('admin.support.noTickets')}</p>
                        ) : (
                            <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
                                {tickets.map((ticket) => (
                                    <button
                                        key={ticket.id}
                                        type="button"
                                        className={`w-full rounded-lg border p-3 text-left transition-colors ${selectedTicketId === ticket.id
                                                ? 'border-primary bg-primary/5'
                                                : 'hover:bg-muted/40'
                                            }`}
                                        onClick={() => setSelectedTicketId(ticket.id)}
                                    >
                                        <div className="flex items-start justify-between gap-2">
                                            <p className="font-medium text-sm line-clamp-2">{ticket.subject}</p>
                                            <Badge variant={getStatusVariant(ticket.status)}>
                                                {t(`settings.support.status.${ticket.status}`)}
                                            </Badge>
                                        </div>
                                        <div className="mt-2 text-xs text-muted-foreground space-y-1">
                                            <div className="flex items-center gap-1">
                                                <Clock3 className="w-3 h-3" />
                                                <span>{formatDate(ticket.created_at)}</span>
                                            </div>
                                            <div>
                                                {t(`settings.support.categories.${ticket.category}`)}
                                                {ticket.is_priority ? ` • ${t('admin.support.priority')}` : ''}
                                            </div>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        )}
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle className="text-base">{t('admin.support.ticketDetails')}</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        {!selectedTicketId ? (
                            <p className="text-sm text-muted-foreground">{t('admin.support.selectTicket')}</p>
                        ) : isLoadingTicket ? (
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                                <Loader2 className="w-4 h-4 animate-spin" />
                                {t('common.loading')}
                            </div>
                        ) : !selectedTicket ? (
                            <p className="text-sm text-muted-foreground">{t('admin.support.ticketLoadError')}</p>
                        ) : (
                            <>
                                <div className="rounded-lg border p-3 space-y-2">
                                    <div className="flex items-center justify-between gap-2">
                                        <p className="font-semibold">{selectedTicket.ticket.subject}</p>
                                        <Badge variant={getStatusVariant(selectedTicket.ticket.status)}>
                                            {t(`settings.support.status.${selectedTicket.ticket.status}`)}
                                        </Badge>
                                    </div>
                                    <div className="text-xs text-muted-foreground space-y-1">
                                        <p>{t(`settings.support.categories.${selectedTicket.ticket.category}`)}</p>
                                        <p>{formatDate(selectedTicket.ticket.created_at)}</p>
                                        <p>
                                            {selectedTicket.ticket.requester_email || t('admin.support.unknownRequester')}
                                        </p>
                                    </div>
                                </div>

                                <div>
                                    <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                                        <MessageSquare className="w-4 h-4" />
                                        {t('admin.support.messages')}
                                    </div>
                                    <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
                                        {selectedTicket.messages.length === 0 ? (
                                            <p className="text-sm text-muted-foreground">{t('admin.support.noMessages')}</p>
                                        ) : (
                                            selectedTicket.messages.map((message) => (
                                                <div key={message.id} className="rounded-lg border p-3 space-y-1">
                                                    <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                                                        <span>{t(`admin.support.author.${message.author_role}`)}</span>
                                                        <div className="flex items-center gap-2">
                                                            {message.is_internal && (
                                                                <Badge variant="outline">{t('admin.support.internalBadge')}</Badge>
                                                            )}
                                                            <span>{formatDate(message.created_at)}</span>
                                                        </div>
                                                    </div>
                                                    <p className="text-sm whitespace-pre-wrap">{message.body}</p>
                                                </div>
                                            ))
                                        )}
                                    </div>
                                </div>

                                {selectedTicket.permissions.can_update_status && canUpdateStatus && (
                                    <div className="rounded-lg border p-3 space-y-2">
                                        <Label>{t('admin.support.statusUpdateLabel')}</Label>
                                        <div className="flex items-center gap-2">
                                            <Select
                                                value={statusUpdate}
                                                onValueChange={(value) =>
                                                    setStatusUpdate(value as AdminSupportTicketStatus)
                                                }
                                            >
                                                <SelectTrigger className="w-full sm:w-[220px]">
                                                    <SelectValue />
                                                </SelectTrigger>
                                                <SelectContent>
                                                    {STATUS_OPTIONS.map((status) => (
                                                        <SelectItem key={status} value={status}>
                                                            {t(`settings.support.status.${status}`)}
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                            <Button onClick={handleStatusUpdate} disabled={isUpdatingStatus}>
                                                {isUpdatingStatus ? (
                                                    <Loader2 className="w-4 h-4 animate-spin" />
                                                ) : (
                                                    t('admin.support.statusUpdateAction')
                                                )}
                                            </Button>
                                        </div>
                                    </div>
                                )}

                                {selectedTicket.permissions.can_reply && canReply && (
                                    <div className="rounded-lg border p-3 space-y-3">
                                        <Label htmlFor="admin-support-reply">{t('admin.support.replyLabel')}</Label>
                                        <Textarea
                                            id="admin-support-reply"
                                            value={replyMessage}
                                            onChange={(event) => setReplyMessage(event.target.value)}
                                            rows={5}
                                            maxLength={5000}
                                            placeholder={t('admin.support.replyPlaceholder')}
                                        />

                                        {selectedTicket.permissions.can_read_internal && canReadInternal && (
                                            <div className="flex items-center gap-2">
                                                <Checkbox
                                                    id="admin-support-reply-internal"
                                                    checked={replyInternal}
                                                    onCheckedChange={(checked) => setReplyInternal(Boolean(checked))}
                                                />
                                                <Label htmlFor="admin-support-reply-internal">
                                                    {t('admin.support.internalNoteToggle')}
                                                </Label>
                                            </div>
                                        )}

                                        <Button
                                            onClick={handleReply}
                                            disabled={isReplying || replyMessage.trim().length < 1}
                                            className="flex items-center gap-2"
                                        >
                                            {isReplying ? (
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                            ) : (
                                                <Send className="w-4 h-4" />
                                            )}
                                            {isReplying ? t('admin.support.replySending') : t('admin.support.replyAction')}
                                        </Button>
                                    </div>
                                )}


                            </>
                        )}
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
