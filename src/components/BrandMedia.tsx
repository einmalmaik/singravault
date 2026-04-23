// Copyright (c) 2025-2026 Maunting Studios
// Licensed under the Business Source License 1.1 - see LICENSE
/**
 * @fileoverview Brand media renderer with static and animated fallbacks.
 *
 * Static PNGs stay the reliable baseline. Optional GIF/WebM/MP4 files can be
 * dropped into public/brand with the configured names and will render on top
 * once the browser confirms that they can play or load.
 */

import { useEffect, useState } from 'react';

interface BrandVideoSource {
  src: string;
  type: string;
}

interface BrandMediaProps {
  alt: string;
  animatedImageSrc?: string;
  fallbackImageSrc: string;
  frameClassName: string;
  height: number;
  loading?: 'eager' | 'lazy';
  mediaClassName: string;
  videoSources?: BrandVideoSource[];
  width: number;
}

const EMPTY_VIDEO_SOURCES: BrandVideoSource[] = [];

async function mediaSourceExists(src: string) {
  try {
    const response = await fetch(src, { method: 'HEAD', cache: 'no-store' });
    return response.ok;
  } catch {
    return false;
  }
}

function usePrefersReducedMotion() {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(() => (
    typeof window !== 'undefined'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false
  ));

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const handleChange = () => setPrefersReducedMotion(mediaQuery.matches);

    handleChange();
    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  return prefersReducedMotion;
}

export function BrandMedia({
  alt,
  animatedImageSrc,
  fallbackImageSrc,
  frameClassName,
  height,
  loading = 'eager',
  mediaClassName,
  videoSources = EMPTY_VIDEO_SOURCES,
  width,
}: BrandMediaProps) {
  const prefersReducedMotion = usePrefersReducedMotion();
  const videoSourceKey = JSON.stringify(videoSources);
  const [availableAnimatedImageSrc, setAvailableAnimatedImageSrc] = useState<string | null>(null);
  const [availableVideoSources, setAvailableVideoSources] = useState<BrandVideoSource[]>(EMPTY_VIDEO_SOURCES);
  const [videoReady, setVideoReady] = useState(false);
  const [videoFailed, setVideoFailed] = useState(false);

  const canUseAnimation = !prefersReducedMotion;
  const hasVideoSources = canUseAnimation && !videoFailed && availableVideoSources.length > 0;
  const showAnimatedImage = canUseAnimation && availableAnimatedImageSrc !== null && !videoReady;
  const showVideo = canUseAnimation && videoReady;

  useEffect(() => {
    let cancelled = false;

    setAvailableAnimatedImageSrc(null);
    setAvailableVideoSources(EMPTY_VIDEO_SOURCES);
    setVideoReady(false);
    setVideoFailed(false);

    if (!canUseAnimation) {
      return () => {
        cancelled = true;
      };
    }

    const detectAnimationSources = async () => {
      const configuredVideoSources = JSON.parse(videoSourceKey) as BrandVideoSource[];
      const existingVideoSources: BrandVideoSource[] = [];
      for (const source of configuredVideoSources) {
        if (await mediaSourceExists(source.src)) {
          existingVideoSources.push(source);
        }
      }

      if (cancelled) return;

      if (existingVideoSources.length > 0) {
        setAvailableVideoSources(existingVideoSources);
        return;
      }

      if (animatedImageSrc && await mediaSourceExists(animatedImageSrc)) {
        if (!cancelled) {
          setAvailableAnimatedImageSrc(animatedImageSrc);
        }
      }
    };

    void detectAnimationSources();

    return () => {
      cancelled = true;
    };
  }, [animatedImageSrc, canUseAnimation, videoSourceKey]);

  return (
    <div className={frameClassName} aria-hidden={alt === '' ? true : undefined}>
      <img
        src={fallbackImageSrc}
        alt={alt}
        width={width}
        height={height}
        className={mediaClassName}
        loading={loading}
        decoding="async"
      />

      {showAnimatedImage ? (
        <img
          src={availableAnimatedImageSrc}
          alt=""
          width={width}
          height={height}
          className={`${mediaClassName} brand-media-overlay brand-media-overlay-visible`}
          loading="lazy"
          decoding="async"
          aria-hidden="true"
          onError={() => setAvailableAnimatedImageSrc(null)}
        />
      ) : null}

      {hasVideoSources ? (
        <video
          className={`${mediaClassName} brand-media-overlay${showVideo ? ' brand-media-overlay-visible' : ''}`}
          poster={fallbackImageSrc}
          preload="metadata"
          autoPlay
          loop
          muted
          playsInline
          aria-hidden="true"
          onCanPlay={() => setVideoReady(true)}
          onError={() => setVideoFailed(true)}
        >
          {availableVideoSources.map((source) => (
            <source key={source.src} src={source.src} type={source.type} />
          ))}
        </video>
      ) : null}
    </div>
  );
}
