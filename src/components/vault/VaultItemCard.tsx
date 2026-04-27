// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Vault Item Card Component
 * 
 * Displays a single vault item with copy actions,
 * password visibility toggle, and favorite indicator.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
    Copy,
    Eye,
    EyeOff,
    Star,
    ExternalLink,
    Key,
    FileText,
    Shield,
    MoreVertical,
    Trash2,
    Edit
} from 'lucide-react';

import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { useToast } from '@/hooks/use-toast';
import { cn } from '@/lib/utils';
import { ViewMode } from '@/pages/VaultPage';
import { VaultItemData } from '@/services/cryptoService';
import { writeClipboard } from '@/services/clipboardService';
import { TOTPDisplay } from './TOTPDisplay';
import { openExternalUrl } from '@/platform/openExternalUrl';

interface VaultItemCardProps {
    item: {
        id: string;
        title: string;
        website_url: string | null;
        item_type: 'password' | 'note' | 'totp' | 'card';
        is_favorite: boolean | null;
        decryptedData?: VaultItemData;
    };
    viewMode: ViewMode;
    onEdit: () => void;
    readOnly?: boolean;
    /** Show the live TOTP code inline. False by default (codes live in AuthenticatorPage).
     *  Set to true only in read-only contexts like GrantorVaultPage where the Authenticator
     *  tab is not accessible but 2FA codes may be needed for account sign-in. */
    showTotpCode?: boolean;
}

export function VaultItemCard({
    item,
    viewMode,
    onEdit,
    readOnly = false,
    showTotpCode = false,
}: VaultItemCardProps) {
    const { t } = useTranslation();
    const { toast } = useToast();
    const [showPassword, setShowPassword] = useState(false);
    const resolvedTitle = item.decryptedData?.title || item.title;
    const resolvedWebsiteUrl = item.decryptedData?.websiteUrl || item.website_url;
    const resolvedItemType = item.decryptedData?.itemType || item.item_type;
    const resolvedIsFavorite = typeof item.decryptedData?.isFavorite === 'boolean'
        ? item.decryptedData.isFavorite
        : !!item.is_favorite;

    const getIcon = () => {
        switch (resolvedItemType) {
            case 'password':
                return <Key className="w-5 h-5" />;
            case 'note':
                return <FileText className="w-5 h-5" />;
            case 'totp':
                return <Shield className="w-5 h-5" />;
            default:
                return <Key className="w-5 h-5" />;
        }
    };

    const getDomainFromUrl = (url: string | null) => {
        if (!url) return null;
        try {
            return new URL(url).hostname;
        } catch {
            return null;
        }
    };

    const copyToClipboard = async (text: string, type: string) => {
        try {
            await writeClipboard(text);
            toast({
                title: t('vault.copied'),
                description: `${t(`vault.copied${type}`)} ${t('vault.clipboardAutoClear')}`,
            });
        } catch {
            toast({
                variant: 'destructive',
                title: t('common.error'),
                description: t('vault.copyFailed'),
            });
        }
    };

    const openUrl = () => {
        if (resolvedWebsiteUrl) {
            void openExternalUrl(resolvedWebsiteUrl).catch(() => {
                toast({
                    variant: 'destructive',
                    title: t('common.error'),
                    description: t('vault.openWebsiteFailed', {
                        defaultValue: 'Link konnte nicht geöffnet werden.',
                    }),
                });
            });
        }
    };

    const domain = getDomainFromUrl(resolvedWebsiteUrl);

    if (viewMode === 'list') {
        return (
            <Card className="border-[hsl(var(--border)/0.4)] bg-[hsl(var(--card)/0.55)] hover:bg-[hsl(var(--el-2)/0.8)] hover:border-[hsl(var(--border)/0.65)] transition-all duration-200">
                <CardContent className="flex items-center gap-4 p-3">
                    {/* Icon */}
                    <div className="flex-shrink-0 p-2 rounded-lg bg-[hsl(var(--primary)/0.1)] border border-[hsl(var(--primary)/0.12)] text-primary">
                        {getIcon()}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                            <h3 className="font-medium truncate">{resolvedTitle}</h3>
                            {resolvedIsFavorite && (
                                <Star className="w-4 h-4 text-amber-500 fill-amber-500 flex-shrink-0" />
                            )}
                        </div>
                        {item.decryptedData?.username && (
                            <p className="text-sm text-muted-foreground truncate">
                                {item.decryptedData.username}
                            </p>
                        )}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-1">
                        {item.decryptedData?.password && (
                            <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                onClick={() => copyToClipboard(item.decryptedData!.password!, 'Password')}
                            >
                                <Copy className="w-4 h-4" />
                            </Button>
                        )}
                        {resolvedWebsiteUrl && (
                            <Button
                                variant="ghost"
                                size="icon"
                                className="h-8 w-8"
                                onClick={openUrl}
                            >
                                <ExternalLink className="w-4 h-4" />
                            </Button>
                        )}
                        {!readOnly && (
                            <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-8 w-8">
                                        <MoreVertical className="w-4 h-4" />
                                    </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                    <DropdownMenuItem onClick={onEdit}>
                                        <Edit className="w-4 h-4 mr-2" />
                                        {t('common.edit')}
                                    </DropdownMenuItem>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem className="text-destructive">
                                        <Trash2 className="w-4 h-4 mr-2" />
                                        {t('common.delete')}
                                    </DropdownMenuItem>
                                </DropdownMenuContent>
                            </DropdownMenu>
                        )}
                    </div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card
            className={cn(
                'group border-[hsl(var(--border)/0.38)] bg-[hsl(var(--card)/0.5)] hover:border-[hsl(var(--primary)/0.22)] hover:bg-[hsl(var(--el-2)/0.7)] hover:shadow-[0_8px_32px_hsl(0_0%_0%/0.3)] transition-all duration-250',
                readOnly ? 'cursor-default' : 'cursor-pointer',
            )}
            onClick={readOnly ? undefined : onEdit}
        >
            <CardContent className="p-4">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-[hsl(var(--primary)/0.1)] border border-[hsl(var(--primary)/0.12)] text-primary group-hover:bg-[hsl(var(--primary)/0.16)] group-hover:border-[hsl(var(--primary)/0.2)] transition-all duration-200">
                            {getIcon()}
                        </div>
                        <div>
                            <h3 className="font-medium line-clamp-1">{resolvedTitle}</h3>
                            {domain && (
                                <p className="text-xs text-muted-foreground">{domain}</p>
                            )}
                        </div>
                    </div>
                    {resolvedIsFavorite && (
                        <Star className="w-4 h-4 text-amber-500 fill-amber-500" />
                    )}
                </div>

                {/* Username */}
                {item.decryptedData?.username && (
                    <div className="mb-2">
                        <p className="text-sm text-muted-foreground truncate">
                            {item.decryptedData.username}
                        </p>
                    </div>
                )}

                {/* Password (if password type) */}
                {resolvedItemType === 'password' && item.decryptedData?.password && (
                    <div className="flex items-center gap-2 mb-3">
                        <code className="flex-1 text-sm bg-[hsl(var(--el-3))] border border-[hsl(var(--border)/0.4)] px-2 py-1 rounded font-mono truncate text-[hsl(var(--accent))]">
                            {showPassword ? item.decryptedData.password : '••••••••••'}
                        </code>
                        <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={(e) => {
                                e.stopPropagation();
                                setShowPassword(!showPassword);
                            }}
                        >
                            {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </Button>
                    </div>
                )}

                {/* TOTP Display — only in contexts where the Authenticator tab is unavailable (e.g. emergency access) */}
                {showTotpCode && resolvedItemType === 'totp' && item.decryptedData?.totpSecret && (
                    <div className="mb-3" onClick={(e) => e.stopPropagation()}>
                        <TOTPDisplay
                            secret={item.decryptedData.totpSecret}
                            algorithm={item.decryptedData.totpAlgorithm}
                            digits={item.decryptedData.totpDigits}
                            period={item.decryptedData.totpPeriod}
                        />
                    </div>
                )}

                {/* Quick Actions */}
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    {item.decryptedData?.username && (
                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(item.decryptedData!.username!, 'Username');
                            }}
                        >
                            <Copy className="w-3 h-3 mr-1" />
                            {t('vault.actions.copyUsername')}
                        </Button>
                    )}
                    {item.decryptedData?.password && (
                        <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs"
                            onClick={(e) => {
                                e.stopPropagation();
                                copyToClipboard(item.decryptedData!.password!, 'Password');
                            }}
                        >
                            <Copy className="w-3 h-3 mr-1" />
                            {t('vault.actions.copyPassword')}
                        </Button>
                    )}
                </div>
            </CardContent>
        </Card>
    );
}
