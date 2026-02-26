// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Health Page
 *
 * Premium feature: Analyzes all vault passwords and displays
 * a comprehensive health report with score, categories, and
 * actionable recommendations.
 */

import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
    Shield,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    Copy,
    Clock,
    RefreshCw,
    ArrowLeft,
    Loader2,
    ChevronRight,
    Lock,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { FeatureGate } from '@/components/Subscription/FeatureGate';
import { useAuth } from '@/contexts/AuthContext';
import { useVault } from '@/contexts/VaultContext';
import { loadVaultSnapshot } from '@/services/offlineVaultService';
import {
    analyzeVaultHealth,
    type HealthReport,
    type HealthIssue,
    type DecryptedPasswordItem,
} from '@/services/vaultHealthService';
import { cn } from '@/lib/utils';
import { Footer } from '@/components/landing/Footer';

// Score ring component
function ScoreRing({ score, size = 160 }: { score: number; size?: number }) {
    const radius = (size - 16) / 2;
    const circumference = 2 * Math.PI * radius;
    const progress = (score / 100) * circumference;
    const color =
        score >= 80 ? 'text-green-500' :
            score >= 60 ? 'text-yellow-500' :
                score >= 40 ? 'text-orange-500' :
                    'text-red-500';

    return (
        <div className="relative" style={{ width: size, height: size }}>
            <svg className="w-full h-full -rotate-90" viewBox={`0 0 ${size} ${size}`}>
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    className="text-muted/30"
                />
                <circle
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    strokeDasharray={`${circumference}`}
                    strokeDashoffset={`${circumference - progress}`}
                    strokeLinecap="round"
                    className={cn('transition-all duration-1000 ease-out', color)}
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={cn('text-4xl font-bold', color)}>{score}</span>
                <span className="text-xs text-muted-foreground mt-1">/ 100</span>
            </div>
        </div>
    );
}

// Issue type configuration
const issueConfig = {
    weak: {
        icon: ShieldAlert,
        color: 'text-red-500',
        bgColor: 'bg-red-500/10',
        borderColor: 'border-red-500/20',
    },
    duplicate: {
        icon: Copy,
        color: 'text-orange-500',
        bgColor: 'bg-orange-500/10',
        borderColor: 'border-orange-500/20',
    },
    old: {
        icon: Clock,
        color: 'text-yellow-500',
        bgColor: 'bg-yellow-500/10',
        borderColor: 'border-yellow-500/20',
    },
    reused: {
        icon: RefreshCw,
        color: 'text-purple-500',
        bgColor: 'bg-purple-500/10',
        borderColor: 'border-purple-500/20',
    },
};

function IssueCard({
    issue,
    onClick,
}: {
    issue: HealthIssue;
    onClick: () => void;
}) {
    const { t } = useTranslation();
    const config = issueConfig[issue.type];
    const Icon = config.icon;

    const getDescription = () => {
        switch (issue.type) {
            case 'weak':
                return t(`vaultHealth.reasons.${issue.description}`, { defaultValue: t('vaultHealth.weakPassword') });
            case 'duplicate':
                return t('vaultHealth.duplicateWith', { items: issue.description });
            case 'old': {
                const days = Math.floor((Date.now() - new Date(issue.description).getTime()) / (1000 * 60 * 60 * 24));
                return t('vaultHealth.oldPassword', { days });
            }
            default:
                return issue.description;
        }
    };

    return (
        <button
            onClick={onClick}
            className={cn(
                'w-full flex items-center gap-3 p-3 rounded-lg border transition-all',
                'hover:bg-accent/50 hover:scale-[1.01] active:scale-[0.99]',
                config.borderColor,
                config.bgColor,
            )}
        >
            <div className={cn('p-2 rounded-lg', config.bgColor)}>
                <Icon className={cn('w-4 h-4', config.color)} />
            </div>
            <div className="flex-1 text-left">
                <p className="font-medium text-sm">{issue.title}</p>
                <p className="text-xs text-muted-foreground">{getDescription()}</p>
            </div>
            <Badge
                variant="outline"
                className={cn(
                    'text-xs',
                    issue.severity === 'critical' && 'border-red-500/50 text-red-500',
                    issue.severity === 'warning' && 'border-orange-500/50 text-orange-500',
                    issue.severity === 'info' && 'border-blue-500/50 text-blue-500',
                )}
            >
                {t(`vaultHealth.severity.${issue.severity}`)}
            </Badge>
            <ChevronRight className="w-4 h-4 text-muted-foreground" />
        </button>
    );
}

export default function VaultHealthPage() {
    const { t } = useTranslation();
    const navigate = useNavigate();
    const { user } = useAuth();
    const { decryptItem, isLocked } = useVault();

    const [report, setReport] = useState<HealthReport | null>(null);
    const [loading, setLoading] = useState(false);
    const [filter, setFilter] = useState<'all' | 'weak' | 'duplicate' | 'old'>('all');

    useEffect(() => {
        if (!user && !loading) navigate('/auth', { replace: true });
    }, [user, loading, navigate]);

    useEffect(() => {
        if (isLocked) navigate('/vault', { replace: true });
    }, [isLocked, navigate]);

    const runAnalysis = useCallback(async () => {
        if (!user) return;
        setLoading(true);
        try {
            const { snapshot } = await loadVaultSnapshot(user.id);
            const passwordItems: DecryptedPasswordItem[] = [];

            for (const item of snapshot.items) {
                try {
                    const decrypted = await decryptItem(item.encrypted_data, item.id);
                    if (decrypted.password) {
                        passwordItems.push({
                            id: item.id,
                            title: decrypted.title || 'Unnamed',
                            password: decrypted.password,
                            username: decrypted.username,
                            websiteUrl: decrypted.websiteUrl || item.website_url || undefined,
                            updatedAt: item.updated_at,
                        });
                    }
                } catch {
                    // Can't decrypt — skip
                }
            }

            const healthReport = analyzeVaultHealth(passwordItems);
            setReport(healthReport);
        } catch (err) {
            console.error('Health analysis failed:', err);
        } finally {
            setLoading(false);
        }
    }, [user, decryptItem]);

    useEffect(() => {
        runAnalysis();
    }, [runAnalysis]);

    const filteredIssues = report?.issues.filter(issue =>
        filter === 'all' || issue.type === filter
    ) || [];

    const getScoreLabel = (score: number) => {
        if (score >= 80) return t('vaultHealth.scoreExcellent');
        if (score >= 60) return t('vaultHealth.scoreGood');
        if (score >= 40) return t('vaultHealth.scoreFair');
        return t('vaultHealth.scorePoor');
    };

    return (
        <div className="min-h-screen flex flex-col bg-gradient-to-br from-primary/5 via-background to-primary/10">
            {/* Header */}
            <header className="sticky top-0 z-50 bg-background/80 backdrop-blur-lg border-b">
                <div className="container max-w-4xl mx-auto px-4 py-4">
                    <div className="flex items-center gap-4">
                        <Button variant="ghost" size="icon" onClick={() => navigate('/vault')}>
                            <ArrowLeft className="w-5 h-5" />
                        </Button>
                        <div className="flex items-center gap-2">
                            <ShieldCheck className="w-6 h-6 text-primary" />
                            <h1 className="text-xl font-bold">{t('vaultHealth.title')}</h1>
                        </div>
                    </div>
                </div>
            </header>

            <main className="container flex-1 max-w-4xl mx-auto px-4 py-8">
                <FeatureGate feature="vault_health_reports">
                    {loading ? (
                        <div className="flex flex-col items-center justify-center py-20 gap-4">
                            <Loader2 className="w-8 h-8 animate-spin text-primary" />
                            <p className="text-muted-foreground">{t('vaultHealth.analyzing')}</p>
                        </div>
                    ) : report ? (
                        <div className="space-y-8">
                            {/* Score Section */}
                            <Card className="overflow-hidden">
                                <div className="bg-gradient-to-r from-primary/10 via-primary/5 to-transparent p-8">
                                    <div className="flex flex-col md:flex-row items-center gap-8">
                                        <ScoreRing score={report.score} />
                                        <div className="text-center md:text-left space-y-2">
                                            <h2 className="text-2xl font-bold">
                                                {getScoreLabel(report.score)}
                                            </h2>
                                            <p className="text-muted-foreground">
                                                {t('vaultHealth.analyzed', {
                                                    count: report.passwordItems,
                                                    total: report.totalItems,
                                                })}
                                            </p>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={runAnalysis}
                                                className="mt-2"
                                            >
                                                <RefreshCw className="w-4 h-4 mr-2" />
                                                {t('vaultHealth.reanalyze')}
                                            </Button>
                                        </div>
                                    </div>
                                </div>
                            </Card>

                            {/* Stats Grid */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                <Card className={cn(
                                    'cursor-pointer transition-all hover:scale-105',
                                    filter === 'weak' && 'ring-2 ring-red-500'
                                )} onClick={() => setFilter(filter === 'weak' ? 'all' : 'weak')}>
                                    <CardContent className="p-4 text-center">
                                        <ShieldAlert className="w-6 h-6 mx-auto text-red-500 mb-2" />
                                        <p className="text-2xl font-bold">{report.stats.weak}</p>
                                        <p className="text-xs text-muted-foreground">{t('vaultHealth.weak')}</p>
                                    </CardContent>
                                </Card>

                                <Card className={cn(
                                    'cursor-pointer transition-all hover:scale-105',
                                    filter === 'duplicate' && 'ring-2 ring-orange-500'
                                )} onClick={() => setFilter(filter === 'duplicate' ? 'all' : 'duplicate')}>
                                    <CardContent className="p-4 text-center">
                                        <Copy className="w-6 h-6 mx-auto text-orange-500 mb-2" />
                                        <p className="text-2xl font-bold">{report.stats.duplicate}</p>
                                        <p className="text-xs text-muted-foreground">{t('vaultHealth.duplicate')}</p>
                                    </CardContent>
                                </Card>

                                <Card className={cn(
                                    'cursor-pointer transition-all hover:scale-105',
                                    filter === 'old' && 'ring-2 ring-yellow-500'
                                )} onClick={() => setFilter(filter === 'old' ? 'all' : 'old')}>
                                    <CardContent className="p-4 text-center">
                                        <Clock className="w-6 h-6 mx-auto text-yellow-500 mb-2" />
                                        <p className="text-2xl font-bold">{report.stats.old}</p>
                                        <p className="text-xs text-muted-foreground">{t('vaultHealth.old')}</p>
                                    </CardContent>
                                </Card>

                                <Card className="transition-all hover:scale-105">
                                    <CardContent className="p-4 text-center">
                                        <ShieldCheck className="w-6 h-6 mx-auto text-green-500 mb-2" />
                                        <p className="text-2xl font-bold">{report.stats.strong}</p>
                                        <p className="text-xs text-muted-foreground">{t('vaultHealth.strong')}</p>
                                    </CardContent>
                                </Card>
                            </div>

                            {/* Issues List */}
                            {filteredIssues.length > 0 ? (
                                <Card>
                                    <CardHeader>
                                        <CardTitle className="flex items-center gap-2 text-base">
                                            <AlertTriangle className="w-5 h-5 text-orange-500" />
                                            {t('vaultHealth.issues')} ({filteredIssues.length})
                                        </CardTitle>
                                    </CardHeader>
                                    <CardContent className="space-y-2">
                                        {filteredIssues.map((issue, i) => (
                                            <IssueCard
                                                key={`${issue.itemId}-${issue.type}-${i}`}
                                                issue={issue}
                                                onClick={() => navigate(`/vault?edit=${issue.itemId}`)}
                                            />
                                        ))}
                                    </CardContent>
                                </Card>
                            ) : report.issues.length === 0 ? (
                                <Card>
                                    <CardContent className="p-12 text-center">
                                        <Shield className="w-12 h-12 mx-auto text-green-500 mb-4" />
                                        <h3 className="text-lg font-semibold">{t('vaultHealth.allGood')}</h3>
                                        <p className="text-muted-foreground mt-2">{t('vaultHealth.allGoodDesc')}</p>
                                    </CardContent>
                                </Card>
                            ) : null}
                        </div>
                    ) : null}
                </FeatureGate>
            </main>
            <Footer />
        </div>
    );
}
