// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Wiederverwendbare Passwort-Stärke-Anzeige
 *
 * Zeigt Score-Balken, Feedback, Crack-Time und HIBP-Warnung.
 */

import { useTranslation } from 'react-i18next';
import { AlertTriangle, Loader2, ShieldAlert } from 'lucide-react';

import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';

// ============ Type Definitions ============

interface PasswordStrengthMeterProps {
    score: 0 | 1 | 2 | 3 | 4;
    feedback: string[];
    crackTimeDisplay: string;
    isPwned: boolean;
    pwnedCount: number;
    isChecking: boolean;
    compact?: boolean;
}

// ============ Score Config ============

const SCORE_CONFIG = [
    { label: 'passwordStrength.veryWeak', className: 'text-destructive', progressClass: '[&>div]:bg-destructive' },
    { label: 'passwordStrength.veryWeak', className: 'text-destructive', progressClass: '[&>div]:bg-destructive' },
    { label: 'passwordStrength.weak', className: 'text-orange-500', progressClass: '[&>div]:bg-orange-500' },
    { label: 'passwordStrength.acceptable', className: 'text-yellow-500', progressClass: '[&>div]:bg-yellow-500' },
    { label: 'passwordStrength.strong', className: 'text-green-500', progressClass: '[&>div]:bg-green-500' },
];

// ============ Component ============

/**
 * Displays password strength meter with score bar, feedback, crack time, and HIBP warning.
 *
 * @param props - Component props
 * @returns Password strength meter JSX
 */
export function PasswordStrengthMeter({
    score,
    feedback,
    crackTimeDisplay,
    isPwned,
    pwnedCount,
    isChecking,
    compact = false,
}: PasswordStrengthMeterProps) {
    const { t } = useTranslation();

    const config = SCORE_CONFIG[score];
    const progressValue = ((score + 1) / 5) * 100;

    return (
        <div className={cn('space-y-1.5', compact && 'space-y-1')}>
            {/* Score bar */}
            <Progress value={progressValue} className={cn('h-2', config.progressClass)} />

            {/* Score label + crack time */}
            <div className="flex items-center justify-between">
                <span className={cn('text-xs font-medium', config.className)}>
                    {t(config.label)}
                </span>
                {crackTimeDisplay && !compact && (
                    <span className="text-xs text-muted-foreground">
                        {t('passwordStrength.crackTime', { time: crackTimeDisplay })}
                    </span>
                )}
            </div>

            {/* Feedback hints */}
            {!compact && feedback.length > 0 && (
                <ul className="space-y-0.5">
                    {feedback.map((hint, i) => (
                        <li key={i} className="text-xs text-muted-foreground flex items-start gap-1">
                            <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0 text-yellow-500" />
                            <span>{hint}</span>
                        </li>
                    ))}
                </ul>
            )}

            {/* HIBP breach warning */}
            {isPwned && (
                <div className="flex items-start gap-1.5 text-xs text-destructive font-medium">
                    <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                    <div>
                        <p>{t('passwordStrength.pwned', { count: pwnedCount })}</p>
                        {!compact && <p className="font-normal">{t('passwordStrength.pwnedWarning')}</p>}
                    </div>
                </div>
            )}

            {/* Checking indicator */}
            {isChecking && (
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    <span>{t('passwordStrength.checking')}</span>
                </div>
            )}
        </div>
    );
}
