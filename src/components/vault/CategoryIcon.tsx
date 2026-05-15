// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Category Icon Component
 * 
 * Renders only category icons approved by categoryIconPolicy.
 * Legacy SVG/text payloads are intentionally ignored for security hardening.
 */

import { cn } from '@/lib/utils';
import { getCategoryIconDefinition } from '@/lib/icons/categoryIconRegistry';
import { normalizeCategoryIcon } from './categoryIconPolicy';

interface CategoryIconProps {
    icon: string | null | undefined;
    className?: string;
    fallbackSize?: number;
}

export function CategoryIcon({ icon, className, fallbackSize = 4 }: CategoryIconProps) {
    const normalizedIcon = normalizeCategoryIcon(icon);
    const definition = getCategoryIconDefinition(normalizedIcon);
    const Icon = definition.Icon;

    return (
        <span
            className={cn('inline-flex items-center justify-center text-current', className)}
            aria-hidden="true"
        >
            <Icon className={cn(`w-${fallbackSize} h-${fallbackSize}`)} />
        </span>
    );
}
