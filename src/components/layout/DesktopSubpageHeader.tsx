import { ArrowLeft, Shield } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { getPrimaryAppPath } from "@/platform/appShell";
import { resolveReturnPath, type ReturnNavigationState } from "@/services/returnNavigationState";

interface DesktopSubpageHeaderProps {
  title: string;
  description?: string;
  defaultBackTo?: string;
}

export function DesktopSubpageHeader({
  title,
  description,
  defaultBackTo,
}: DesktopSubpageHeaderProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as ReturnNavigationState | null;
  const primaryAppPath = getPrimaryAppPath();
  const backTo = resolveReturnPath(state, defaultBackTo || primaryAppPath);

  return (
    <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto flex h-16 max-w-5xl items-center justify-between px-4">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="icon" onClick={() => navigate(backTo)}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div className="min-w-0">
            <h1 className="truncate text-lg font-semibold">{title}</h1>
            {description ? (
              <p className="truncate text-sm text-muted-foreground">{description}</p>
            ) : null}
          </div>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => navigate(primaryAppPath)}
          className="flex items-center gap-2"
        >
          <Shield className="h-4 w-4" />
          <span className="hidden sm:inline">Tresor</span>
        </Button>
      </div>
    </header>
  );
}
