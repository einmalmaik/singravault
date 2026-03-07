// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Cookie settings dialog aligned with the Singra Core AI consent UI.
 */

import { useTranslation } from 'react-i18next';
import { BarChart3, Shield, Sparkles } from 'lucide-react';

import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { COOKIE_DIALOG_COPY } from '@/components/cookieConsentContent';

interface CookieSettingsDialogProps {
    open: boolean;
    optional: boolean;
    onOpenChange: (open: boolean) => void;
    onOptionalChange: (value: boolean) => void;
    onSave: () => void;
}

export function CookieSettingsDialog({
    open,
    optional,
    onOpenChange,
    onOptionalChange,
    onSave,
}: CookieSettingsDialogProps) {
    const { i18n } = useTranslation();
    const language = i18n.language.startsWith('de') ? 'de' : 'en';
    const copy = COOKIE_DIALOG_COPY[language];
    const necessaryItems = copy.categories.necessary.items;
    const functionalItems = copy.categories.functional.items;
    const analyticsItems = copy.categories.analytics.items;

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                    <DialogTitle>{copy.title}</DialogTitle>
                    <DialogDescription>{copy.description}</DialogDescription>
                </DialogHeader>

                <div className="space-y-6 py-4">
                    <div className="space-y-3">
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex gap-3 flex-1">
                                <div className="flex-shrink-0 mt-1">
                                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                                        <Shield className="h-5 w-5 text-primary" />
                                    </div>
                                </div>
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                        <Label className="text-base font-semibold">
                                            {copy.categories.necessary.title}
                                        </Label>
                                        <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground font-medium">
                                            {copy.requiredBadge}
                                        </span>
                                    </div>
                                    <p className="text-sm text-muted-foreground mb-2">
                                        {copy.categories.necessary.description}
                                    </p>
                                    <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                                        {necessaryItems.map((item) => (
                                            <li key={item}>{item}</li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                            <Switch checked disabled className="mt-1" />
                        </div>
                    </div>

                    <Separator />

                    <div className="space-y-3">
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex gap-3 flex-1">
                                <div className="flex-shrink-0 mt-1">
                                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                                        <Sparkles className="h-5 w-5 text-primary" />
                                    </div>
                                </div>
                                <div className="flex-1">
                                    <Label htmlFor="functional" className="text-base font-semibold mb-1 block">
                                        {copy.categories.functional.title}
                                    </Label>
                                    <p className="text-sm text-muted-foreground mb-2">
                                        {copy.categories.functional.description}
                                    </p>
                                    <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                                        {functionalItems.map((item) => (
                                            <li key={item}>{item}</li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                            <Switch
                                id="functional"
                                checked={optional}
                                onCheckedChange={onOptionalChange}
                                className="mt-1"
                            />
                        </div>
                    </div>

                    <Separator />

                    <div className="space-y-3 opacity-60">
                        <div className="flex items-start justify-between gap-4">
                            <div className="flex gap-3 flex-1">
                                <div className="flex-shrink-0 mt-1">
                                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                                        <BarChart3 className="h-5 w-5 text-primary" />
                                    </div>
                                </div>
                                <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                        <Label className="text-base font-semibold">
                                            {copy.categories.analytics.title}
                                        </Label>
                                        <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground font-medium">
                                            {copy.unavailableBadge}
                                        </span>
                                    </div>
                                    <p className="text-sm text-muted-foreground mb-2">
                                        {copy.categories.analytics.description}
                                    </p>
                                    <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                                        {analyticsItems.map((item) => (
                                            <li key={item}>{item}</li>
                                        ))}
                                    </ul>
                                </div>
                            </div>
                            <Switch checked={false} disabled className="mt-1" />
                        </div>
                    </div>
                </div>

                <DialogFooter>
                    <Button onClick={onSave} className="w-full sm:w-auto">
                        {copy.save}
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
