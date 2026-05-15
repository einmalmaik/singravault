// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE

import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';

import { cn } from '@/lib/utils';

type VaultItemPreviewPanelBreakpoint = 'lg' | 'xl';

interface VaultItemPreviewPanelProps {
  children: ReactNode;
  breakpoint?: VaultItemPreviewPanelBreakpoint;
  className?: string;
  contentClassName?: string;
}

const breakpointClasses: Record<VaultItemPreviewPanelBreakpoint, {
  panel: string;
  content: string;
}> = {
  lg: {
    panel: 'lg:inset-x-auto lg:bottom-auto lg:right-0 lg:top-0 lg:h-[100dvh] lg:w-[22rem] lg:max-h-[100dvh] lg:border-l lg:border-t-0 lg:slide-in-from-right-8',
    content: 'lg:p-5 lg:pt-[calc(1.25rem+var(--safe-area-top))] lg:pb-[calc(1.25rem+var(--safe-area-bottom))]',
  },
  xl: {
    panel: 'xl:inset-x-auto xl:bottom-auto xl:right-0 xl:top-0 xl:h-[100dvh] xl:w-[22rem] xl:max-h-[100dvh] xl:border-l xl:border-t-0 xl:slide-in-from-right-8',
    content: 'xl:p-5 xl:pt-[calc(1.25rem+var(--safe-area-top))] xl:pb-[calc(1.25rem+var(--safe-area-bottom))]',
  },
};

export function VaultItemPreviewPanel({
  children,
  breakpoint = 'lg',
  className,
  contentClassName,
}: VaultItemPreviewPanelProps) {
  const classes = breakpointClasses[breakpoint];

  const panel = (
    <aside
      className={cn(
        'fixed inset-x-0 bottom-0 z-50 max-h-[86vh] overflow-hidden border-t border-border/55 bg-[radial-gradient(circle_at_top_left,hsl(var(--primary)/0.08),transparent_34%),linear-gradient(180deg,hsl(var(--el-2)/0.98),hsl(var(--background)/0.98))] shadow-[0_-20px_56px_hsl(0_0%_0%/0.48)] backdrop-blur-xl animate-in fade-in slide-in-from-bottom-8 duration-300',
        classes.panel,
        className,
      )}
    >
      <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-primary/35 to-transparent" />
      <div
        className={cn(
          'h-full max-h-[inherit] overflow-y-auto p-4 pb-[calc(1rem+var(--safe-area-bottom))]',
          classes.content,
          contentClassName,
        )}
      >
        {children}
      </div>
    </aside>
  );

  return createPortal(panel, document.body);
}
