// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Safe provider/category icon renderer for vault surfaces.
 */

import { cn } from '@/lib/utils';
import { getBrandIconDefinition } from '@/lib/icons/brandIconRegistry';
import { resolveBrandIconId, type ProviderMatchInput } from '@/lib/icons/providerMatcher';

interface VaultIconProps extends ProviderMatchInput {
  className?: string;
  iconClassName?: string;
  label?: string | null;
  decorative?: boolean;
}

export function VaultIcon({
  className,
  iconClassName,
  decorative = true,
  ...providerInput
}: VaultIconProps) {
  const iconId = resolveBrandIconId(providerInput);
  const definition = getBrandIconDefinition(iconId);
  const Icon = definition.Icon;
  const label = providerInput.label ?? definition.label;

  return (
    <span
      className={cn(
        'inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border bg-[hsl(var(--el-2)/0.88)] shadow-[0_0_24px_hsl(var(--primary)/0.08)]',
        className,
      )}
      style={{
        borderColor: `${definition.accent}55`,
        color: definition.accent,
      }}
      aria-hidden={decorative ? true : undefined}
      aria-label={decorative ? undefined : label}
      title={label}
    >
      {definition.svgSrc && definition.renderMode === 'image' ? (
        <img
          src={definition.svgSrc}
          alt=""
          className={cn('h-5 w-5 object-contain', iconClassName)}
          loading="lazy"
          decoding="async"
          draggable={false}
        />
      ) : definition.svgSrc ? (
        <span
          className={cn('h-5 w-5', iconClassName)}
          style={{
            backgroundColor: definition.accent,
            maskImage: `url(${definition.svgSrc})`,
            maskPosition: 'center',
            maskRepeat: 'no-repeat',
            maskSize: 'contain',
            WebkitMaskImage: `url(${definition.svgSrc})`,
            WebkitMaskPosition: 'center',
            WebkitMaskRepeat: 'no-repeat',
            WebkitMaskSize: 'contain',
          }}
          aria-hidden="true"
        />
      ) : (
        <Icon className={cn('h-5 w-5', iconClassName)} />
      )}
    </span>
  );
}
