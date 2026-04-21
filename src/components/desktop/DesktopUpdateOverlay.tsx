import {
  AlertTriangle,
  Download,
  Loader2,
  RotateCw,
  ShieldCheck,
} from "lucide-react";

import { Progress } from "@/components/ui/progress";
import {
  type DesktopUpdateStage,
  useDesktopUpdateState,
} from "@/services/desktopUpdateStore";

const stageIcons: Record<
  DesktopUpdateStage,
  {
    icon: typeof Loader2;
    iconClassName: string;
  }
> = {
  idle: {
    icon: Loader2,
    iconClassName: "text-primary",
  },
  checking: {
    icon: Loader2,
    iconClassName: "animate-spin text-primary",
  },
  upToDate: {
    icon: ShieldCheck,
    iconClassName: "text-emerald-400",
  },
  downloading: {
    icon: Download,
    iconClassName: "text-primary",
  },
  installing: {
    icon: RotateCw,
    iconClassName: "animate-spin text-primary",
  },
  restarting: {
    icon: RotateCw,
    iconClassName: "animate-spin text-emerald-400",
  },
  error: {
    icon: AlertTriangle,
    iconClassName: "text-amber-400",
  },
};

function resolveProgress(stage: DesktopUpdateStage, progress: number | null): number {
  if (typeof progress === "number") {
    return progress;
  }

  switch (stage) {
    case "checking":
      return 28;
    case "upToDate":
      return 100;
    case "downloading":
      return 52;
    case "installing":
      return 84;
    case "restarting":
      return 100;
    case "error":
      return 100;
    default:
      return 0;
  }
}

export function DesktopUpdateOverlay() {
  const state = useDesktopUpdateState();

  if (!state.visible) {
    return null;
  }

  const { icon: Icon, iconClassName } = stageIcons[state.stage];
  const progressValue = resolveProgress(state.stage, state.progress);

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center bg-[hsl(206_31%_4%/0.98)] px-6">
      <div className="absolute inset-0 bg-[radial-gradient(65%_65%_at_20%_20%,hsl(var(--primary)/0.2)_0%,transparent_65%),radial-gradient(45%_45%_at_82%_18%,hsl(188_70%_60%/0.12)_0%,transparent_72%),radial-gradient(40%_40%_at_50%_100%,hsl(204_80%_25%/0.22)_0%,transparent_70%)]" />

      <div className="relative w-full max-w-xl rounded-lg border border-[hsl(193_45%_86%/0.14)] bg-[hsl(204_25%_10%/0.76)] p-8 shadow-[0_24px_80px_hsl(0_0%_0%/0.45)] backdrop-blur-xl">
        <div className="mb-6 flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-lg border border-[hsl(193_45%_86%/0.16)] bg-[hsl(193_45%_86%/0.08)]">
            <Icon className={`h-7 w-7 ${iconClassName}`} />
          </div>
          <div>
            <div className="text-xs font-medium uppercase tracking-[0.28em] text-[hsl(193_45%_86%/0.7)]">
              Singra Vault
            </div>
            <h2 className="text-2xl font-semibold text-[hsl(188_29%_95%)]">
              {state.title}
            </h2>
          </div>
        </div>

        <p className="mb-6 text-sm leading-7 text-[hsl(196_19%_75%)]">
          {state.message}
        </p>

        <div className="space-y-3">
          <Progress
            value={progressValue}
            className="h-2 bg-[hsl(193_45%_86%/0.12)]"
          />
          <div className="flex items-center justify-between text-xs text-[hsl(196_19%_67%)]">
            <span>{state.detail || "\u00A0"}</span>
            {state.version ? <span>v{state.version}</span> : <span>{"\u00A0"}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
