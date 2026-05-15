// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Sidebar Item Row
 *
 * Generic clickable row used both for the quick navigation entries (All
 * items, Vault Health, Authenticator) and the dynamic categories. Supports
 * a collapsed icon-only mode, an "active" highlight, a count/badge slot and
 * a disabled state with optional reason tooltip for premium-gated entries.
 */

import { cn } from '@/lib/utils';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';

interface VaultSidebarItemProps {
  readonly icon: React.ReactNode;
  readonly label: string;
  readonly count?: number;
  readonly badge?: string;
  readonly collapsed?: boolean;
  readonly active?: boolean;
  readonly disabled?: boolean;
  readonly disabledReason?: string;
  readonly variant?: 'default' | 'destructive';
  readonly color?: string | null;
  readonly onClick?: () => void;
}

export function VaultSidebarItem({
  icon,
  label,
  count,
  badge,
  collapsed,
  active,
  disabled,
  disabledReason,
  variant = 'default',
  color,
  onClick,
}: VaultSidebarItemProps) {
  const content = (
    <button
      onClick={onClick}
      aria-disabled={disabled}
      className={cn(
        'flex min-h-11 w-full items-center gap-3 rounded-lg px-3 py-2.5 transition-all duration-150 lg:min-h-0',
        'text-[hsl(var(--sidebar-foreground)/0.72)] hover:text-[hsl(var(--sidebar-foreground))]',
        'hover:bg-[hsl(var(--el-2)/0.82)]',
        active && 'border border-primary/25 bg-[hsl(var(--primary)/0.12)] text-[hsl(var(--sidebar-primary))] shadow-[0_0_24px_hsl(var(--primary)/0.08)]',
        variant === 'destructive' && 'text-destructive hover:bg-destructive/10 hover:text-destructive',
        disabled && 'cursor-not-allowed opacity-45 hover:bg-transparent hover:text-[hsl(var(--sidebar-foreground)/0.72)]',
        collapsed && 'justify-center px-0',
      )}
    >
      <span style={color ? { color } : undefined}>{icon}</span>
      {!collapsed && (
        <>
          <span className="flex-1 truncate text-left text-sm">{label}</span>
          {count !== undefined && count > 0 && (
            <span className="text-xs text-muted-foreground">{count}</span>
          )}
          {badge && (
            <span className="rounded-full border border-primary/20 bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
              {badge}
            </span>
          )}
        </>
      )}
    </button>
  );

  if (collapsed || disabledReason) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          {content}
        </TooltipTrigger>
        <TooltipContent side="right">
          <p>{label}</p>
          {disabledReason && <p className="text-xs text-muted-foreground">{disabledReason}</p>}
        </TooltipContent>
      </Tooltip>
    );
  }

  return content;
}
