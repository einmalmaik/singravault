import type { ReactNode } from "react";

import { DesktopSubpageHeader } from "@/components/layout/DesktopSubpageHeader";

interface DesktopSubpageFrameProps {
  title: string;
  description?: string;
  defaultBackTo?: string;
  children: ReactNode;
}

export function DesktopSubpageFrame({
  title,
  description,
  defaultBackTo,
  children,
}: DesktopSubpageFrameProps) {
  return (
    <div className="min-h-screen bg-background">
      <DesktopSubpageHeader
        title={title}
        description={description}
        defaultBackTo={defaultBackTo}
      />

      <main className="container mx-auto max-w-5xl px-4 py-8">{children}</main>
    </div>
  );
}
