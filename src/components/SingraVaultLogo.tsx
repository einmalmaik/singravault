/**
 * @fileoverview SingraVault Logo Component
 * 
 * SVG logo based on singra-core-ai design with vault-specific styling.
 */

interface SingraVaultLogoProps {
  size?: number;
  className?: string;
  showWordmark?: boolean;
}

export const SingraVaultLogo = ({ 
  size = 36, 
  className = "",
  showWordmark = false 
}: SingraVaultLogoProps) => {
  const s = size;
  const cx = s / 2;
  const cy = s / 2;
  const r1 = s * 0.38;  // Outer ring
  const r2 = s * 0.28;  // Inner ring
  const r3 = s * 0.15;  // Core

  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <svg
        width={s}
        height={s}
        viewBox={`0 0 ${s} ${s}`}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0"
        aria-hidden="true"
      >
        <defs>
          {/* Core glow gradient */}
          <radialGradient id="singravault-core-glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="hsl(193, 60%, 85%)" stopOpacity="0.9" />
            <stop offset="40%" stopColor="hsl(193, 50%, 60%)" stopOpacity="0.4" />
            <stop offset="100%" stopColor="hsl(193, 40%, 30%)" stopOpacity="0" />
          </radialGradient>
          
          {/* Void/core gradient */}
          <radialGradient id="singravault-void" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="hsl(206, 31%, 4%)" stopOpacity="1" />
            <stop offset="60%" stopColor="hsl(206, 31%, 4%)" stopOpacity="0.8" />
            <stop offset="100%" stopColor="hsl(206, 31%, 4%)" stopOpacity="0" />
          </radialGradient>
          
          {/* Outer ring gradient */}
          <linearGradient id="singravault-ring-outer" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="hsl(193, 45%, 75%)" stopOpacity="0.8" />
            <stop offset="50%" stopColor="hsl(193, 40%, 55%)" stopOpacity="0.3" />
            <stop offset="100%" stopColor="hsl(193, 45%, 75%)" stopOpacity="0.7" />
          </linearGradient>
          
          {/* Inner ring gradient */}
          <linearGradient id="singravault-ring-inner" x1="0%" y1="100%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="hsl(193, 50%, 80%)" stopOpacity="0.6" />
            <stop offset="50%" stopColor="hsl(193, 40%, 50%)" stopOpacity="0.2" />
            <stop offset="100%" stopColor="hsl(193, 50%, 80%)" stopOpacity="0.5" />
          </linearGradient>
          
          {/* Glow filter */}
          <filter id="singravault-glow-filter" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="1.5" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Ambient glow */}
        <circle cx={cx} cy={cy} r={r1 + 2} fill="url(#singravault-core-glow)" opacity="0.5" />

        {/* Vault-like outer ring with lock aesthetic */}
        <ellipse
          cx={cx}
          cy={cy}
          rx={r1}
          ry={r1 * 0.35}
          stroke="url(#singravault-ring-outer)"
          strokeWidth="1.2"
          fill="none"
          filter="url(#singravault-glow-filter)"
          transform={`rotate(-15, ${cx}, ${cy})`}
        />

        {/* Inner security ring */}
        <ellipse
          cx={cx}
          cy={cy}
          rx={r2}
          ry={r2 * 0.4}
          stroke="url(#singravault-ring-inner)"
          strokeWidth="0.8"
          fill="none"
          filter="url(#singravault-glow-filter)"
          transform={`rotate(25, ${cx}, ${cy})`}
        />

        {/* Vault core with singularity effect */}
        <circle cx={cx} cy={cy} r={r3} fill="url(#singravault-core-glow)" />
        <circle cx={cx} cy={cy} r={r3 * 0.4} fill="url(#singravault-void)" />

        {/* Accretion particles */}
        <circle cx={cx - r1 * 0.3} cy={cy - r1 * 0.1} r="1.2" fill="hsl(193, 50%, 85%)" opacity="0.7" />
        <circle cx={cx + r1 * 0.35} cy={cy + r1 * 0.05} r="0.8" fill="hsl(193, 50%, 85%)" opacity="0.5" />
        <circle cx={cx + r1 * 0.1} cy={cy - r1 * 0.3} r="1" fill="hsl(193, 50%, 85%)" opacity="0.6" />
      </svg>

      {/* Wordmark - only shown if requested */}
      {showWordmark && (
        <div className="flex flex-col leading-none">
          <span className="text-lg font-bold tracking-tight text-foreground">SingraVault</span>
          <span className="text-[0.6rem] uppercase tracking-[0.2em] text-muted-foreground">Password Manager</span>
        </div>
      )}
    </div>
  );
};
