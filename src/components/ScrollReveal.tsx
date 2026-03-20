// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 — see LICENSE
/**
 * @fileoverview Scroll-triggered reveal animation wrapper
 *
 * Uses IntersectionObserver to animate children into view as they
 * enter the viewport. Respects prefers-reduced-motion.
 */

import { useEffect, useRef, type ReactNode } from 'react';

interface ScrollRevealProps {
    children: ReactNode;
    className?: string;
    delay?: number;
    threshold?: number;
    /** 'up' (default), 'fade' (opacity only), 'scale' */
    variant?: 'up' | 'fade' | 'scale';
    as?: 'div' | 'section' | 'article';
}

export function ScrollReveal({
    children,
    className = '',
    delay = 0,
    threshold = 0.12,
    variant = 'up',
    as: Tag = 'div',
}: ScrollRevealProps) {
    const ref = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;

        const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (prefersReduced) {
            el.classList.add('sr-visible');
            return;
        }

        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    const timer = delay
                        ? window.setTimeout(() => el.classList.add('sr-visible'), delay)
                        : (el.classList.add('sr-visible'), 0);
                    observer.disconnect();
                    return () => window.clearTimeout(timer);
                }
            },
            { threshold },
        );

        observer.observe(el);
        return () => observer.disconnect();
    }, [delay, threshold]);

    const variantClass = `sr-${variant}`;

    return (
        // @ts-expect-error polymorphic ref
        <Tag ref={ref} className={`scroll-reveal ${variantClass} ${className}`}>
            {children}
        </Tag>
    );
}

/**
 * Staggered grid — children animate in one by one as the container enters view.
 */
interface ScrollRevealGridProps {
    children: ReactNode;
    className?: string;
    threshold?: number;
    staggerMs?: number;
}

export function ScrollRevealGrid({
    children,
    className = '',
    threshold = 0.1,
    staggerMs = 80,
}: ScrollRevealGridProps) {
    const ref = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const el = ref.current;
        if (!el) return;

        const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (prefersReduced) {
            el.classList.add('sg-visible');
            return;
        }

        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    const items = el.querySelectorAll<HTMLElement>(':scope > *');
                    items.forEach((item, i) => {
                        item.style.setProperty('--sg-delay', `${i * staggerMs}ms`);
                    });
                    el.classList.add('sg-visible');
                    observer.disconnect();
                }
            },
            { threshold },
        );

        observer.observe(el);
        return () => observer.disconnect();
    }, [threshold, staggerMs]);

    return (
        <div ref={ref} className={`stagger-grid ${className}`}>
            {children}
        </div>
    );
}
