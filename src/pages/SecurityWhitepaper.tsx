// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Security Whitepaper Page
 *
 * Public-facing, code-backed explanation of Singra Vault's security model.
 * This page is intentionally factual and references concrete implementation
 * details present in the repository.
 */

import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
    Shield,
    KeyRound,
    Lock,
    Database,
    File,
    Users,
    WifiOff,
    Clipboard,
    AlertTriangle,
    ExternalLink,
    MonitorSmartphone,
    Fingerprint,
} from 'lucide-react';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { DesktopSubpageHeader } from '@/components/layout/DesktopSubpageHeader';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { cn } from '@/lib/utils';
import { SEO, createArticleStructuredData, createBreadcrumbStructuredData } from '@/components/SEO';

import { Header } from '@/components/landing/Header';
import { Footer } from '@/components/landing/Footer';
import { shouldShowWebsiteChrome } from '@/platform/appShell';

type WhitepaperTag =
    | 'auth'
    | 'crypto'
    | 'client'
    | 'rls'
    | 'storage'
    | 'sharing'
    | 'offline'
    | 'integrity'
    | 'hardening'
    | 'limitations';

interface WhitepaperSection {
    id: string;
    tags: WhitepaperTag[];
    icon: JSX.Element;
    title: string;
    summary: string;
    bullets: string[];
    evidence: string[];
}

const SECURITY_WHITEPAPER_LAST_UPDATED = '28.04.2026';

function asStringArray(value: unknown): string[] {
    if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
        return value;
    }
    return [];
}

export default function SecurityWhitepaper() {
    const { t } = useTranslation();
    const [query, setQuery] = useState('');
    const [activeTags, setActiveTags] = useState<Set<WhitepaperTag>>(new Set());
    const showWebsiteChrome = shouldShowWebsiteChrome();

    // Scroll to top on mount (fixes navigation from other pages)
    useEffect(() => {
        window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }, []);

    const tagMeta = useMemo(() => {
        const tags: Array<{ id: WhitepaperTag; label: string }> = [
            { id: 'crypto', label: t('securityWhitepaper.tags.crypto') },
            { id: 'auth', label: t('securityWhitepaper.tags.auth') },
            { id: 'client', label: t('securityWhitepaper.tags.client') },
            { id: 'rls', label: t('securityWhitepaper.tags.rls') },
            { id: 'storage', label: t('securityWhitepaper.tags.storage') },
            { id: 'sharing', label: t('securityWhitepaper.tags.sharing') },
            { id: 'offline', label: t('securityWhitepaper.tags.offline') },
            { id: 'integrity', label: t('securityWhitepaper.tags.integrity') },
            { id: 'hardening', label: t('securityWhitepaper.tags.hardening') },
            { id: 'limitations', label: t('securityWhitepaper.tags.limitations') },
        ];
        return tags;
    }, [t]);

    const sections = useMemo<WhitepaperSection[]>(() => {
        return [
            {
                id: 'zero-knowledge',
                tags: ['crypto', 'client'],
                icon: <Shield className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.zeroKnowledge.title'),
                summary: t('securityWhitepaper.sections.zeroKnowledge.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.zeroKnowledge.bullets', { returnObjects: true }),
                ),
                evidence: [
                    'src/services/cryptoService.ts',
                    'src/components/vault/VaultItemDialog.tsx',
                    'src/components/settings/DataSettings.tsx',
                ],
            },
            {
                id: 'cryptography',
                tags: ['crypto', 'client'],
                icon: <KeyRound className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.cryptography.title'),
                summary: t('securityWhitepaper.sections.cryptography.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.cryptography.bullets', { returnObjects: true }),
                ),
                evidence: ['src/services/cryptoService.ts'],
            },
            {
                id: 'memory-handling',
                tags: ['client', 'hardening', 'limitations'],
                icon: <Lock className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.memory.title'),
                summary: t('securityWhitepaper.sections.memory.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.memory.bullets', { returnObjects: true }),
                ),
                evidence: [
                    'src/contexts/VaultContext.tsx',
                    'src/services/cryptoService.ts',
                    'src/services/secureBuffer.ts',
                ],
            },
            {
                id: 'clipboard',
                tags: ['client', 'hardening', 'limitations'],
                icon: <Clipboard className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.clipboard.title'),
                summary: t('securityWhitepaper.sections.clipboard.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.clipboard.bullets', { returnObjects: true }),
                ),
                evidence: ['src/services/clipboardService.ts'],
            },
            {
                id: 'xss-same-origin',
                tags: ['client', 'hardening', 'limitations'],
                icon: <Shield className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.xssSameOrigin.title'),
                summary: t('securityWhitepaper.sections.xssSameOrigin.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.xssSameOrigin.bullets', { returnObjects: true })),
                evidence: [
                    'src/platform/openExternalUrl.ts',
                    'src/services/postAuthRedirectService.ts',
                    'src/services/returnNavigationState.ts',
                    'src/services/exportFileService.ts',
                    '@singra/premium/src/services/fileAttachmentService.ts',
                    'vite.config.ts',
                    'vercel.json',
                    'src-tauri/tauri.conf.json',
                    'docs/xss-same-origin-hardening-2026-04-28.md',
                    'OWASP XSS / DOM-XSS / CSP Cheat Sheets, MDN CSP, MDN Trusted Types, React dangerouslySetInnerHTML documentation, Tauri CSP documentation',
                ],
            },
            {
                id: 'rls',
                tags: ['rls', 'hardening'],
                icon: <Database className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.rls.title'),
                summary: t('securityWhitepaper.sections.rls.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.rls.bullets', { returnObjects: true })),
                evidence: [
                    'supabase/migrations/20260210180000_subscription_system.sql',
                    'supabase/migrations/20260210181100_emergency_access_policies.sql',
                    'supabase/migrations/20260211000000_fix_shared_collections_rls.sql',
                ],
            },
            {
                id: 'attachments',
                tags: ['storage', 'crypto'],
                icon: <File className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.attachments.title'),
                summary: t('securityWhitepaper.sections.attachments.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.attachments.bullets', { returnObjects: true }),
                ),
                evidence: [
                    '@singra/premium/src/services/fileAttachmentService.ts',
                    'supabase/migrations/20260213120000_secure_vault_attachments_bucket.sql',
                    'supabase/migrations/20260426143000_file_attachment_e2ee_chunked_limits.sql',
                    'docs/premium-file-upload-e2ee.md',
                    'scripts/check-release-artifacts.mjs',
                ],
            },
            {
                id: 'sharing',
                tags: ['sharing', 'crypto'],
                icon: <Users className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.sharing.title'),
                summary: t('securityWhitepaper.sections.sharing.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.sharing.bullets', { returnObjects: true })),
                evidence: [
                    'supabase/migrations/20260210180000_subscription_system.sql',
                    'supabase/migrations/20260211000000_fix_shared_collections_rls.sql',
                    'src/services/cryptoService.ts',
                ],
            },
            {
                id: 'offline',
                tags: ['offline', 'client', 'limitations'],
                icon: <WifiOff className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.offline.title'),
                summary: t('securityWhitepaper.sections.offline.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.offline.bullets', { returnObjects: true })),
                evidence: ['src/services/offlineVaultService.ts', 'src/contexts/VaultContext.tsx'],
            },
            {
                id: 'authentication',
                tags: ['auth', 'client', 'hardening'],
                icon: <Lock className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.authentication.title'),
                summary: t('securityWhitepaper.sections.authentication.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.authentication.bullets', { returnObjects: true }),
                ),
                evidence: [
                    'src/pages/Auth.tsx',
                    'src/services/opaqueService.ts',
                    'src/services/accountPasswordResetService.ts',
                    'supabase/functions/auth-opaque/index.ts',
                    'supabase/functions/auth-session/index.ts',
                    'supabase/functions/auth-register/index.ts',
                    'supabase/functions/auth-recovery/index.ts',
                    'supabase/functions/auth-reset-password/index.ts',
                ],
            },
            {
                id: 'device-keys',
                tags: ['crypto', 'client', 'storage', 'limitations'],
                icon: <MonitorSmartphone className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.deviceKeys.title'),
                summary: t('securityWhitepaper.sections.deviceKeys.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.deviceKeys.bullets', { returnObjects: true })),
                evidence: [
                    'src/services/deviceKeyService.ts',
                    'src/platform/localSecretStore.ts',
                    'src-tauri/src/lib.rs',
                    'docs/DEVICE_KEY.md',
                ],
            },
            {
                id: 'sessions-webauthn',
                tags: ['auth', 'client', 'hardening'],
                icon: <Fingerprint className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.sessionsWebAuthn.title'),
                summary: t('securityWhitepaper.sections.sessionsWebAuthn.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.sessionsWebAuthn.bullets', { returnObjects: true })),
                evidence: [
                    'src/services/authSessionManager.ts',
                    'supabase/functions/auth-session/index.ts',
                    'supabase/functions/webauthn/index.ts',
                    'supabase/migrations/20260427211000_bind_webauthn_challenges_to_scope.sql',
                ],
            },
            {
                id: 'recovery-emergency',
                tags: ['sharing', 'crypto', 'limitations'],
                icon: <AlertTriangle className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.recoveryEmergency.title'),
                summary: t('securityWhitepaper.sections.recoveryEmergency.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.recoveryEmergency.bullets', { returnObjects: true })),
                evidence: [
                    'supabase/functions/auth-recovery/index.ts',
                    'src/services/vaultRecoveryService.ts',
                    '@singra/premium/src/services/emergencyAccessService.ts',
                    '@singra/premium/src/components/settings/EmergencyAccessSettings.tsx',
                    'supabase/migrations/20260427212000_harden_emergency_access_and_sync_heads.sql',
                ],
            },
            {
                id: 'categories',
                tags: ['crypto', 'client', 'offline', 'integrity'],
                icon: <Database className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.categories.title'),
                summary: t('securityWhitepaper.sections.categories.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.categories.bullets', { returnObjects: true })),
                evidence: [
                    'src/components/vault/CategoryDialog.tsx:200 (loadItemsInCategory: Eintrag-zu-Kategorie-Zuordnung)',
                    'src/components/vault/CategoryDialog.tsx:264 (handleDelete: Nur Kategorie vs. Kategorie + Einträge)',
                    'src/services/offlineVaultService.ts:411 (applyOfflineCategoryDeletion: ein lokaler Snapshot-Write)',
                    'src/components/vault/VaultSidebar.tsx:124 (race-sicherer Kategorie-Refresh)',
                    'src/components/vault/categoryIconPolicy.ts:9 (zulässige Icon-Presets; kein SVG-Input)',
                ],
            },
            {
                id: 'integrity',
                tags: ['integrity', 'crypto', 'limitations'],
                icon: <AlertTriangle className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.integrity.title'),
                summary: t('securityWhitepaper.sections.integrity.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.integrity.bullets', { returnObjects: true }),
                ),
                evidence: [
                    'src/services/vaultIntegrityService.ts:131 (inspectVaultSnapshotIntegrity)',
                    'src/services/vaultIntegrityService.ts:377 (computeVaultSnapshotDigest)',
                    'src/services/vaultIntegrityService.ts:494 (detectItemDigestDrift)',
                    'src/services/vaultIntegrityService.ts:540 (detectCategoryDigestDriftIds)',
                    'src/contexts/VaultContext.tsx:1052 (refreshIntegrityBaseline)',
                    'src/contexts/VaultContext.tsx:2412 (verifyIntegrity)',
                    'src/components/vault/VaultIntegrityRecovery.tsx',
                ],
            },
            {
                id: 'headers',
                tags: ['hardening', 'client'],
                icon: <Shield className="h-5 w-5 text-primary" />,
                title: t('securityWhitepaper.sections.headers.title'),
                summary: t('securityWhitepaper.sections.headers.summary'),
                bullets: asStringArray(t('securityWhitepaper.sections.headers.bullets', { returnObjects: true })),
                evidence: ['vite.config.ts'],
            },
            {
                id: 'limits',
                tags: ['limitations'],
                icon: <AlertTriangle className="h-5 w-5 text-destructive" />,
                title: t('securityWhitepaper.sections.limitations.title'),
                summary: t('securityWhitepaper.sections.limitations.summary'),
                bullets: asStringArray(
                    t('securityWhitepaper.sections.limitations.bullets', { returnObjects: true }),
                ),
                evidence: [
                    'src/services/secureBuffer.ts',
                    'vite.config.ts',
                    'supabase/migrations/20260210180000_subscription_system.sql',
                ],
            },
        ];
    }, [t]);

    const normalizedQuery = query.trim().toLowerCase();

    const filteredSections = useMemo(() => {
        return sections.filter((section) => {
            if (activeTags.size > 0) {
                const matchesTag = section.tags.some((tag) => activeTags.has(tag));
                if (!matchesTag) return false;
            }

            if (!normalizedQuery) return true;

            const haystack = [section.title, section.summary, ...section.bullets].join(' ').toLowerCase();
            return haystack.includes(normalizedQuery);
        });
    }, [sections, activeTags, normalizedQuery]);

    const toggleTag = (tag: WhitepaperTag) => {
        setActiveTags((prev) => {
            const next = new Set(prev);
            if (next.has(tag)) next.delete(tag);
            else next.add(tag);
            return next;
        });
    };

    // Structured data for SEO
    const structuredData = {
        ...createArticleStructuredData({
            title: 'Security Whitepaper - Singra Vault',
            description: 'Faktenbasierte Beschreibung der Sicherheitsarchitektur von Singra Vault – direkt aus dem Code und den DB-Policies abgeleitet.',
            path: '/security',
        }),
        ...createBreadcrumbStructuredData([
            { name: 'Home', path: '/' },
            { name: 'Security Whitepaper', path: '/security' },
        ]),
    };

    return (
        <div className="min-h-screen bg-background flex flex-col">
            <SEO
                title="Security Whitepaper"
                description="Faktenbasierte Beschreibung der Sicherheitsarchitektur von Singra Vault: clientseitige Vault-Payload-Verschlüsselung, Argon2id, AES-GCM, Row Level Security und dokumentierte Grenzen."
                path="/security"
                keywords={[
                    'Security Whitepaper',
                    'Zero-Knowledge Vault Payloads',
                    'Argon2id',
                    'AES-GCM',
                    'Row Level Security',
                    'Clientseitige Verschlüsselung',
                    'End-to-End Encryption',
                    'Kryptographie',
                    'Datensicherheit',
                ]}
                structuredData={structuredData}
            />
            {showWebsiteChrome ? (
                <Header />
            ) : (
                <DesktopSubpageHeader
                    title={t('securityWhitepaper.title')}
                    description={t('securityWhitepaper.subtitle')}
                />
            )}
            <main className={`flex-grow px-4 sm:px-6 lg:px-8 ${showWebsiteChrome ? 'py-28' : 'py-6'}`}>
                <div className="mx-auto w-full max-w-5xl space-y-8">
                    {/* Hero Section */}
                    <div className="relative overflow-hidden rounded-2xl border bg-card">
                        <div className="absolute inset-0 bg-[radial-gradient(60%_60%_at_30%_20%,hsl(var(--primary)/0.18)_0%,transparent_70%),radial-gradient(50%_50%_at_80%_60%,hsl(var(--secondary)/0.25)_0%,transparent_70%)]" />
                        <div className="relative p-6 sm:p-10">
                            <div className="space-y-4 max-w-3xl">
                                <h1 className="text-3xl sm:text-4xl font-bold tracking-tight">
                                    {t('securityWhitepaper.title')}
                                </h1>
                                <p className="text-lg text-muted-foreground">
                                    {t('securityWhitepaper.subtitle')}
                                </p>
                                <p className="text-sm text-muted-foreground">
                                    {t('securityWhitepaper.disclaimer')}{' '}
                                    <Link to="/privacy" className="underline underline-offset-4 hover:text-foreground">
                                        {t('securityWhitepaper.privacyLink')}
                                    </Link>
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Quick Facts - Full Width Grid */}
                    <Card>
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <Shield className="h-5 w-5 text-primary" />
                                {t('securityWhitepaper.quickFacts.title')}
                            </CardTitle>
                            <CardDescription>{t('securityWhitepaper.quickFacts.subtitle')}</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <div className="grid gap-4 sm:grid-cols-2">
                                {asStringArray(t('securityWhitepaper.quickFacts.items', { returnObjects: true })).map((line, idx) => (
                                    <div key={idx} className="flex items-start gap-3 rounded-lg border bg-muted/30 p-4">
                                        <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary" />
                                        <span className="text-sm text-muted-foreground leading-relaxed">{line}</span>
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>

                    <Card>
                        <CardHeader className="space-y-3">
                            <div className="flex items-center justify-between gap-4 flex-col sm:flex-row">
                                <div className="w-full sm:max-w-md">
                                    <Input
                                        value={query}
                                        onChange={(e) => setQuery(e.target.value)}
                                        placeholder={t('securityWhitepaper.searchPlaceholder')}
                                    />
                                </div>
                                <div className="flex items-center gap-2 self-start sm:self-auto">
                                    <Button
                                        type="button"
                                        variant="outline"
                                        size="sm"
                                        onClick={() => {
                                            setQuery('');
                                            setActiveTags(new Set());
                                        }}
                                        disabled={query.length === 0 && activeTags.size === 0}
                                    >
                                        {t('securityWhitepaper.clearFilters')}
                                    </Button>
                                </div>
                            </div>

                            <div className="flex flex-wrap gap-2">
                                {tagMeta.map((tag) => (
                                    <button
                                        key={tag.id}
                                        type="button"
                                        onClick={() => toggleTag(tag.id)}
                                        className={cn('transition', activeTags.has(tag.id) ? '' : 'opacity-80 hover:opacity-100')}
                                    >
                                        <Badge variant={activeTags.has(tag.id) ? 'default' : 'secondary'}>
                                            {tag.label}
                                        </Badge>
                                    </button>
                                ))}
                            </div>
                        </CardHeader>
                    </Card>

                    <ScrollArea className="w-full rounded-md">
                        <Accordion type="multiple" className="w-full space-y-4">
                            {filteredSections.length === 0 ? (
                                <Card>
                                    <CardContent className="py-10 text-center text-muted-foreground">
                                        {t('common.noResults')}
                                    </CardContent>
                                </Card>
                            ) : (
                                filteredSections.map((section) => (
                                    <AccordionItem key={section.id} value={section.id} className="border-b-0">
                                        <Card className="overflow-hidden">
                                            <AccordionTrigger className="px-6 py-4 hover:no-underline">
                                                <div className="flex items-start gap-3 text-left">
                                                    <div className="mt-0.5 rounded-full bg-primary/10 p-2">
                                                        {section.icon}
                                                    </div>
                                                    <div className="space-y-1">
                                                        <div className="flex flex-wrap items-center gap-2">
                                                            <span className="text-lg font-semibold">{section.title}</span>
                                                            {section.tags.includes('limitations') ? (
                                                                <Badge variant="destructive">{t('securityWhitepaper.badges.limitation')}</Badge>
                                                            ) : null}
                                                        </div>
                                                        <p className="text-sm text-muted-foreground">{section.summary}</p>
                                                    </div>
                                                </div>
                                            </AccordionTrigger>
                                            <AccordionContent className="px-6 pb-6">
                                                <div className="space-y-4">
                                                    <div className="flex flex-wrap gap-2">
                                                        {section.tags.map((tag) => (
                                                            <Badge key={tag} variant="outline">
                                                                {tagMeta.find((t2) => t2.id === tag)?.label ?? tag}
                                                            </Badge>
                                                        ))}
                                                    </div>

                                                    <div className="space-y-2">
                                                        {section.bullets.map((line) => (
                                                            <div key={line} className="flex items-start gap-2">
                                                                <span className="mt-2 h-1.5 w-1.5 rounded-full bg-muted-foreground/70" />
                                                                <p className="text-sm text-muted-foreground leading-relaxed">{line}</p>
                                                            </div>
                                                        ))}
                                                    </div>

                                                    <div className="rounded-lg border bg-muted/30 p-4">
                                                        <div className="text-xs font-semibold text-muted-foreground mb-2">
                                                            {t('securityWhitepaper.evidenceTitle')}
                                                        </div>
                                                        <div className="flex flex-col gap-1">
                                                            {section.evidence.map((ref) => (
                                                                <code key={ref} className="text-xs text-muted-foreground">
                                                                    {ref}
                                                                </code>
                                                            ))}
                                                        </div>
                                                    </div>
                                                </div>
                                            </AccordionContent>
                                        </Card>
                                    </AccordionItem>
                                ))
                            )}
                        </Accordion>
                    </ScrollArea>

                    <Card>
                        <CardHeader>
                            <CardTitle className="text-base">{t('securityWhitepaper.references.title')}</CardTitle>
                            <CardDescription>{t('securityWhitepaper.references.subtitle')}</CardDescription>
                        </CardHeader>
                        <CardContent className="flex flex-col gap-2 text-sm">
                            <a
                                href="https://bitwarden.com/help/bitwarden-security-white-paper/"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground"
                            >
                                <ExternalLink className="h-4 w-4" />
                                {t('securityWhitepaper.references.links.bitwarden')}
                            </a>
                            <a
                                href="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground"
                            >
                                <ExternalLink className="h-4 w-4" />
                                {t('securityWhitepaper.references.links.owaspPasswordStorage')}
                            </a>
                            <a
                                href="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground"
                            >
                                <ExternalLink className="h-4 w-4" />
                                {t('securityWhitepaper.references.links.owaspCsp')}
                            </a>
                            <a
                                href="https://pages.nist.gov/800-63-3/sp800-63b.html"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground"
                            >
                                <ExternalLink className="h-4 w-4" />
                                {t('securityWhitepaper.references.links.nist80063b')}
                            </a>
                            <div className="pt-2 text-xs text-muted-foreground">
                                {t('securityWhitepaper.lastUpdated', { date: SECURITY_WHITEPAPER_LAST_UPDATED })}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </main>
            {showWebsiteChrome && <Footer />}
        </div>
    );
}
