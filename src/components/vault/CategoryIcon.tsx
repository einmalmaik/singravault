// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Category Icon Component
 * 
 * Renders only category icons approved by categoryIconPolicy.
 * Legacy SVG/text payloads are intentionally ignored for security hardening.
 */

import { Folder } from 'lucide-react';
import { cn } from '@/lib/utils';
import { normalizeCategoryIcon } from './categoryIconPolicy';

interface CategoryIconProps {
    icon: string | null | undefined;
    className?: string;
    fallbackSize?: number;
}

export function CategoryIcon({ icon, className, fallbackSize = 4 }: CategoryIconProps) {
    const normalizedIcon = normalizeCategoryIcon(icon);
    if (!normalizedIcon) {
        return <Folder className={cn(`w-${fallbackSize} h-${fallbackSize}`, className)} />;
    }

    return (
        <span className={cn('text-base leading-none', className)}>
            {normalizedIcon}
        </span>
    );
}
