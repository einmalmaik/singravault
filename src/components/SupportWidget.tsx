// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Floating Support Widget
 *
 * Global floating widget accessible on all pages. Provides quick access to support
 * ticket creation, ticket list with unread indicators, and per-ticket chat view.
 */

import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import {
    ArrowLeft,
    LifeBuoy,
    X,
    XCircle,
    Send,
    Loader2,
    Clock3,
    MessageSquare,
    ShieldAlert,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
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
    Card,
    CardContent,
    CardHeader,
    CardTitle,
} from '@/components/ui/card';

import { useAuth } from '@/contexts/AuthContext';

import { useToast } from '@/hooks/use-toast';
import {
    getSupportTicketDetail,
    listSupportTickets,
    closeSupportTicket,
    replySupportTicket,
    submitSupportTicket,
    type CreateSupportTicketInput,
    type SupportEntitlement,
    type SupportMessage,
    type SupportTicketSummary,
} from '@/services/supportService';

const CATEGORY_OPTIONS: Array<CreateSupportTicketInput['category']> = [
    'general',
    'technical',
    'billing',
    'security',
    'family',
    'other',
];

const POLL_INTERVAL_MS = 30_000;

/**
 * Floating support widget button + panel.
 *
 * @returns Floating support widget
 */
export function SupportWidget() {
    const { user } = useAuth();
    const { t, i18n } = useTranslation();
    const { toast } = useToast();

    const [isOpen, setIsOpen] = useState(false);
    const [activeTab, setActiveTab] = useState<'create' | 'tickets' | 'chat'>('create');

    // Create ticket form
    const [subject, setSubject] = useState('');
    const [category, setCategory] = useState<CreateSupportTicketInput['category']>('general');
    const [message, setMessage] = useState('');

    // Loading states
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [isLoadingChat, setIsLoadingChat] = useState(false);
    const [isSendingReply, setIsSendingReply] = useState(false);
    const [isClosingTicket, setIsClosingTicket] = useState(false);

    // Data
    const [entitlement, setEntitlement] = useState<SupportEntitlement | null>(null);
    const [tickets, setTickets] = useState<SupportTicketSummary[]>([]);

    // Chat state
    const [selectedTicketId, setSelectedTicketId] = useState<string | null>(null);
    const [selectedTicket, setSelectedTicket] = useState<SupportTicketSummary | null>(null);
    const [chatMessages, setChatMessages] = useState<SupportMessage[]>([]);
    const [replyText, setReplyText] = useState('');
    const chatBottomRef = useRef<HTMLDivElement>(null);
    const prevUnreadTotalRef = useRef(-1);

    const currentSlaText = useMemo(() => {
        const slaHours = entitlement?.sla_hours ?? 72;
        if (slaHours <= 24) {
            return t('settings.support.sla.priority24h');
        }
        return t('settings.support.sla.standard72h');
    }, [entitlement?.sla_hours, t]);

    const isPriority = entitlement?.is_priority ?? false;

    const totalUnread = useMemo(() => {
        return tickets.reduce((sum, ticket) => sum + (ticket.unread_count || 0), 0);
    }, [tickets]);

    /**
     * Sends a push notification via the service worker when new support replies arrive.
     */
    const fireSupportNotification = useCallback(() => {
        if (!('Notification' in window) || Notification.permission !== 'granted') {
            return;
        }

        if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage({
                type: 'SUPPORT_REPLY_NOTIFICATION',
                title: t('settings.support.chat.newReplyNotification'),
                body: t('settings.support.chat.newReplyBody'),
                url: '/vault',
            });
        } else {
            // Fallback: direct Notification API
            new Notification(t('settings.support.chat.newReplyNotification'), {
                body: t('settings.support.chat.newReplyBody'),
                icon: '/singra-icon.png',
            });
        }
    }, [t]);

    const loadSupportData = useCallback(async () => {
        setIsLoading(true);
        try {
            const { entitlement: ent, tickets: tix, error: loadError } = await listSupportTickets();
            if (loadError) {
                console.error('Failed to load support tickets:', loadError);
                return;
            }
            setEntitlement(ent);

            // Detect new unread replies and fire a browser notification
            const newTotal = tix.reduce((sum, ticket) => sum + (ticket.unread_count || 0), 0);

            if (prevUnreadTotalRef.current >= 0 && newTotal > prevUnreadTotalRef.current) {
                fireSupportNotification();
            }
            prevUnreadTotalRef.current = newTotal;

            setTickets(tix);
        } catch (err) {
            console.error('Error loading support data:', err);
        } finally {
            setIsLoading(false);
        }
    }, [fireSupportNotification]);

    const loadChatDetail = useCallback(async (ticketId: string) => {
        setIsLoadingChat(true);
        try {
            const { ticket, messages, error } = await getSupportTicketDetail(ticketId);

            if (error || !ticket) {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('settings.support.chat.loadError'),
                });
                return;
            }

            setSelectedTicket(ticket);
            setChatMessages(messages);
        } catch (err) {
            console.error('Error loading chat detail:', err);
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.support.chat.loadError'),
            });
        } finally {
            setIsLoadingChat(false);
        }
    }, [t, toast]);

    // Load support data when widget opens
    useEffect(() => {
        if (isOpen && user) {
            void loadSupportData();
        }
    }, [isOpen, user, loadSupportData]);

    // Poll for new messages while chat is open
    useEffect(() => {
        if (!isOpen || !user || activeTab !== 'chat' || !selectedTicketId) {
            return;
        }

        const interval = setInterval(() => {
            void loadChatDetail(selectedTicketId);
        }, POLL_INTERVAL_MS);

        return () => clearInterval(interval);
    }, [isOpen, user, activeTab, selectedTicketId, loadChatDetail]);

    // Poll ticket list for unread counts while on tickets tab
    useEffect(() => {
        if (!isOpen || !user || activeTab !== 'tickets') {
            return;
        }

        const interval = setInterval(() => {
            void loadSupportData();
        }, POLL_INTERVAL_MS);

        return () => clearInterval(interval);
    }, [isOpen, user, activeTab, loadSupportData]);

    // Scroll to bottom when new messages arrive
    useEffect(() => {
        chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatMessages]);

    // Load chat detail when ticket selected
    useEffect(() => {
        if (selectedTicketId && activeTab === 'chat') {
            void loadChatDetail(selectedTicketId);
        }
    }, [selectedTicketId, activeTab, loadChatDetail]);

    // Request notification permission when widget opens
    useEffect(() => {
        if (isOpen && user && 'Notification' in window && Notification.permission === 'default') {
            void Notification.requestPermission();
        }
    }, [isOpen, user]);

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
        setActiveTab('tickets');
    };

    const handleOpenChat = (ticketId: string) => {
        setSelectedTicketId(ticketId);
        setReplyText('');
        setActiveTab('chat');
    };

    const handleBackToTickets = async () => {
        setSelectedTicketId(null);
        setSelectedTicket(null);
        setChatMessages([]);
        setActiveTab('tickets');
        await loadSupportData();
    };

    const handleSendReply = async () => {
        if (!selectedTicketId || replyText.trim().length < 1) {
            return;
        }

        setIsSendingReply(true);
        const { error } = await replySupportTicket(selectedTicketId, replyText.trim());
        setIsSendingReply(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.support.chat.sendError'),
            });
            return;
        }

        setReplyText('');
        await loadChatDetail(selectedTicketId);
    };

    const handleCloseTicket = async () => {
        if (!selectedTicketId) {
            return;
        }

        setIsClosingTicket(true);
        const { error } = await closeSupportTicket(selectedTicketId);
        setIsClosingTicket(false);

        if (error) {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('settings.support.chat.closeError'),
            });
            return;
        }

        toast({
            title: t('common.success'),
            description: t('settings.support.chat.closeSuccess'),
        });

        await loadChatDetail(selectedTicketId);
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

    const getStatusVariant = (status: SupportTicketSummary['status']) => {
        if (status === 'resolved' || status === 'closed') {
            return 'secondary' as const;
        }
        if (status === 'in_progress') {
            return 'default' as const;
        }
        return 'outline' as const;
    };

    if (!user) {
        return null;
    }

    return (
        <>
            {/* Floating Button */}
            {!isOpen && (
                <button
                    onClick={() => setIsOpen(true)}
                    className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-full bg-primary px-4 py-3 text-primary-foreground shadow-lg hover:bg-primary/90 transition-all"
                    aria-label={t('settings.support.title')}
                >
                    <LifeBuoy className="w-5 h-5" />
                    <span className="hidden sm:inline font-medium">Support</span>
                    {totalUnread > 0 && (
                        <span className="absolute -top-1 -right-1 flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-destructive-foreground">
                            {totalUnread > 9 ? '9+' : totalUnread}
                        </span>
                    )}
                </button>
            )}

            {/* Floating Panel */}
            {isOpen && (
                <div className="fixed bottom-6 right-6 z-50 w-[90vw] max-w-md h-[600px] flex flex-col shadow-2xl rounded-lg border bg-background">
                    <Card className="flex flex-col h-full border-0 shadow-none">
                        <CardHeader className="flex-shrink-0 border-b pb-3">
                            <div className="flex items-center justify-between">
                                <CardTitle className="flex items-center gap-2 text-lg">
                                    {activeTab === 'chat' && (
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            className="h-7 w-7"
                                            onClick={() => void handleBackToTickets()}
                                        >
                                            <ArrowLeft className="w-4 h-4" />
                                        </Button>
                                    )}
                                    <LifeBuoy className="w-5 h-5" />
                                    {activeTab === 'chat'
                                        ? t('settings.support.chat.title')
                                        : t('settings.support.title')}
                                </CardTitle>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    onClick={() => setIsOpen(false)}
                                >
                                    <X className="w-4 h-4" />
                                </Button>
                            </div>

                            {activeTab !== 'chat' && (
                                <>
                                    {/* SLA Badge */}
                                    <div className="flex items-center gap-2 mt-2">
                                        <Clock3 className="w-4 h-4 text-muted-foreground" />
                                        <Badge variant={isPriority ? 'default' : 'secondary'} className="text-xs">
                                            {currentSlaText}
                                        </Badge>
                                    </div>

                                    {/* Tabs */}
                                    <div className="flex gap-2 mt-3">
                                        <Button
                                            variant={activeTab === 'create' ? 'default' : 'outline'}
                                            size="sm"
                                            onClick={() => setActiveTab('create')}
                                            className="flex-1"
                                        >
                                            {t('settings.support.newTicket')}
                                        </Button>
                                        <Button
                                            variant={activeTab === 'tickets' ? 'default' : 'outline'}
                                            size="sm"
                                            onClick={() => setActiveTab('tickets')}
                                            className="flex-1 relative"
                                        >
                                            {t('settings.support.myTickets')}
                                            {totalUnread > 0 && (
                                                <span className="ml-1.5 inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[10px] font-bold text-destructive-foreground">
                                                    {totalUnread}
                                                </span>
                                            )}
                                        </Button>
                                    </div>
                                </>
                            )}

                            {activeTab === 'chat' && selectedTicket && (
                                <div className="mt-2 space-y-1">
                                    <p className="text-sm font-medium line-clamp-1">{selectedTicket.subject}</p>
                                    <div className="flex items-center gap-2">
                                        <Badge variant={getStatusVariant(selectedTicket.status)} className="text-xs">
                                            {t(`settings.support.status.${selectedTicket.status}`)}
                                        </Badge>
                                        <span className="text-xs text-muted-foreground">
                                            {t(`settings.support.categories.${selectedTicket.category}`)}
                                        </span>
                                    </div>
                                </div>
                            )}
                        </CardHeader>

                        <CardContent className="flex-1 overflow-y-auto p-4 space-y-4">
                            {/* ============ CREATE TAB ============ */}
                            {activeTab === 'create' && (
                                <>
                                    <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
                                        <div className="flex items-start gap-2">
                                            <ShieldAlert className="w-3.5 h-3.5 mt-0.5 text-amber-600" />
                                            <p>{t('settings.support.securityHint')}</p>
                                        </div>
                                    </div>

                                    <div className="space-y-3">
                                        <div className="space-y-1.5">
                                            <Label htmlFor="widget-subject" className="text-sm">
                                                {t('settings.support.subject')}
                                            </Label>
                                            <Input
                                                id="widget-subject"
                                                value={subject}
                                                onChange={(e) => setSubject(e.target.value)}
                                                maxLength={160}
                                                placeholder={t('settings.support.subjectPlaceholder')}
                                                className="text-sm"
                                            />
                                        </div>

                                        <div className="space-y-1.5">
                                            <Label className="text-sm">{t('settings.support.category')}</Label>
                                            <Select
                                                value={category}
                                                onValueChange={(value) =>
                                                    setCategory(value as CreateSupportTicketInput['category'])
                                                }
                                            >
                                                <SelectTrigger className="w-full text-sm">
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

                                        <div className="space-y-1.5">
                                            <Label htmlFor="widget-message" className="text-sm">
                                                {t('settings.support.message')}
                                            </Label>
                                            <Textarea
                                                id="widget-message"
                                                value={message}
                                                onChange={(e) => setMessage(e.target.value)}
                                                minLength={10}
                                                maxLength={5000}
                                                rows={8}
                                                placeholder={t('settings.support.messagePlaceholder')}
                                                className="text-sm resize-none"
                                            />
                                        </div>

                                        <Button
                                            onClick={handleSubmit}
                                            disabled={isSubmitting}
                                            className="w-full flex items-center gap-2"
                                            size="sm"
                                        >
                                            {isSubmitting ? (
                                                <Loader2 className="w-4 h-4 animate-spin" />
                                            ) : (
                                                <Send className="w-4 h-4" />
                                            )}
                                            {isSubmitting
                                                ? t('settings.support.submitting')
                                                : t('settings.support.submit')}
                                        </Button>
                                    </div>
                                </>
                            )}

                            {/* ============ TICKETS TAB ============ */}
                            {activeTab === 'tickets' && (
                                <div className="space-y-3">
                                    {isLoading && (
                                        <div className="text-sm text-muted-foreground flex items-center gap-2">
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                            {t('common.loading')}
                                        </div>
                                    )}

                                    {!isLoading && tickets.length === 0 && (
                                        <p className="text-sm text-muted-foreground">
                                            {t('settings.support.noTickets')}
                                        </p>
                                    )}

                                    {!isLoading &&
                                        tickets.map((ticket) => (
                                            <button
                                                key={ticket.id}
                                                type="button"
                                                onClick={() => handleOpenChat(ticket.id)}
                                                className="w-full rounded-lg border p-3 space-y-2 hover:bg-muted/30 transition-colors text-left"
                                            >
                                                <div className="flex items-start justify-between gap-2">
                                                    <div className="flex items-center gap-2 min-w-0">
                                                        {(ticket.unread_count || 0) > 0 && (
                                                            <span className="flex-shrink-0 flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1 text-[10px] font-bold text-primary-foreground">
                                                                {ticket.unread_count}
                                                            </span>
                                                        )}
                                                        <p className="font-medium text-sm line-clamp-2">
                                                            {ticket.subject}
                                                        </p>
                                                    </div>
                                                    <Badge variant={getStatusVariant(ticket.status)} className="text-xs flex-shrink-0">
                                                        {t(`settings.support.status.${ticket.status}`)}
                                                    </Badge>
                                                </div>
                                                <div className="flex flex-wrap gap-1.5 text-xs text-muted-foreground">
                                                    <span>{t(`settings.support.categories.${ticket.category}`)}</span>
                                                    <span>·</span>
                                                    <span>{formatDate(ticket.created_at)}</span>
                                                </div>
                                                {ticket.latest_message && (
                                                    <div className="flex items-start gap-1.5 text-xs text-muted-foreground mt-1">
                                                        <MessageSquare className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                                        <p className="line-clamp-1">{ticket.latest_message.body}</p>
                                                    </div>
                                                )}
                                            </button>
                                        ))}
                                </div>
                            )}

                            {/* ============ CHAT TAB ============ */}
                            {activeTab === 'chat' && (
                                <div className="flex flex-col h-full -my-4 -mx-4">
                                    {isLoadingChat && chatMessages.length === 0 ? (
                                        <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">
                                            <Loader2 className="w-4 h-4 animate-spin mr-2" />
                                            {t('common.loading')}
                                        </div>
                                    ) : (
                                        <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
                                            {chatMessages.map((msg) => {
                                                const isUser = msg.author_role === 'user';
                                                return (
                                                    <div
                                                        key={msg.id}
                                                        className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}
                                                    >
                                                        <div
                                                            className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${isUser
                                                                ? 'bg-primary text-primary-foreground'
                                                                : 'bg-muted'
                                                                }`}
                                                        >
                                                            <p className="whitespace-pre-wrap break-words">{msg.body}</p>
                                                            <p className={`text-[10px] mt-1 ${isUser ? 'text-primary-foreground/70' : 'text-muted-foreground'}`}>
                                                                {isUser
                                                                    ? t('settings.support.chat.you')
                                                                    : t('settings.support.chat.support')}
                                                                {' · '}
                                                                {formatDate(msg.created_at)}
                                                            </p>
                                                        </div>
                                                    </div>
                                                );
                                            })}
                                            <div ref={chatBottomRef} />
                                        </div>
                                    )}

                                    {/* Reply input + close button */}
                                    {selectedTicket && selectedTicket.status !== 'closed' && (
                                        <div className="flex-shrink-0 border-t px-4 py-3 space-y-2">
                                            <div className="flex items-end gap-2">
                                                <Textarea
                                                    value={replyText}
                                                    onChange={(e) => setReplyText(e.target.value)}
                                                    onKeyDown={(e) => {
                                                        if (e.key === 'Enter' && !e.shiftKey) {
                                                            e.preventDefault();
                                                            void handleSendReply();
                                                        }
                                                    }}
                                                    maxLength={5000}
                                                    rows={2}
                                                    placeholder={t('settings.support.chat.replyPlaceholder')}
                                                    className="text-sm resize-none flex-1"
                                                />
                                                <Button
                                                    size="icon"
                                                    disabled={isSendingReply || replyText.trim().length < 1}
                                                    onClick={() => void handleSendReply()}
                                                    className="flex-shrink-0"
                                                >
                                                    {isSendingReply ? (
                                                        <Loader2 className="w-4 h-4 animate-spin" />
                                                    ) : (
                                                        <Send className="w-4 h-4" />
                                                    )}
                                                </Button>
                                            </div>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                disabled={isClosingTicket}
                                                onClick={() => void handleCloseTicket()}
                                                className="w-full text-xs text-muted-foreground"
                                            >
                                                {isClosingTicket ? (
                                                    <Loader2 className="w-3 h-3 animate-spin mr-1.5" />
                                                ) : (
                                                    <XCircle className="w-3 h-3 mr-1.5" />
                                                )}
                                                {t('settings.support.chat.closeTicket')}
                                            </Button>
                                        </div>
                                    )}

                                    {selectedTicket && selectedTicket.status === 'closed' && (
                                        <div className="flex-shrink-0 border-t px-4 py-3 text-center text-xs text-muted-foreground">
                                            {t('settings.support.chat.ticketClosed')}
                                        </div>
                                    )}
                                </div>
                            )}
                        </CardContent>
                    </Card>
                </div>
            )}
        </>
    );
}
