import { useEffect } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  resetDesktopUpdateState,
  setDesktopUpdateState,
  type DesktopUpdateState,
} from "@/services/desktopUpdateStore";

const previewStates: Record<string, DesktopUpdateState> = {
  checking: {
    visible: true,
    stage: "checking",
    title: "Prüfe auf Updates",
    message:
      "Singra Vault gleicht diese Desktop-Installation mit dem neuesten Release ab.",
    detail: "Bitte einen Moment warten",
    progress: null,
    version: null,
  },
  upToDate: {
    visible: true,
    stage: "upToDate",
    title: "Aktueller Stand",
    message: "Diese Installation ist bereits auf dem neuesten Stand.",
    detail: "Die App wird jetzt geöffnet",
    progress: 100,
    version: null,
  },
  downloading: {
    visible: true,
    stage: "downloading",
    title: "Update 1.4.2 wird vorbereitet",
    message:
      "Das Update wird geladen und anschließend automatisch installiert.",
    detail: "42% geladen",
    progress: 42,
    version: "1.4.2",
  },
  installing: {
    visible: true,
    stage: "installing",
    title: "Update 1.4.2 wird installiert",
    message:
      "Die neue Version wird eingebunden. Danach startet Singra Vault neu.",
    detail: "Installation wird abgeschlossen",
    progress: 100,
    version: "1.4.2",
  },
  restarting: {
    visible: true,
    stage: "restarting",
    title: "Neustart",
    message:
      "Die neue Version ist installiert. Singra Vault startet jetzt neu.",
    detail: "Desktop-App wird neu gestartet",
    progress: 100,
    version: "1.4.2",
  },
  error: {
    visible: true,
    stage: "error",
    title: "Updateprüfung fehlgeschlagen",
    message:
      "Die App startet normal weiter. Beim nächsten Start wird erneut geprüft.",
    detail: "Could not fetch a valid release JSON from the remote",
    progress: 100,
    version: null,
  },
};

const previewOrder = [
  "checking",
  "upToDate",
  "downloading",
  "installing",
  "restarting",
  "error",
] as const;

export default function DesktopUpdatePreviewPage() {
  const [searchParams] = useSearchParams();
  const requestedStage = searchParams.get("stage") ?? "checking";
  const activeStage = requestedStage in previewStates ? requestedStage : "checking";
  const hideControls = searchParams.get("controls") === "0";

  useEffect(() => {
    setDesktopUpdateState(previewStates[activeStage]);

    return () => {
      resetDesktopUpdateState();
    };
  }, [activeStage]);

  return (
    <div className="min-h-screen bg-background">
      {!hideControls && (
        <div className="fixed right-6 top-6 z-[130] w-full max-w-sm rounded-lg border border-border/60 bg-card/92 p-4 shadow-2xl backdrop-blur-xl">
          <div className="mb-3">
            <p className="text-sm font-semibold text-foreground">
              Desktop-Update-Vorschau
            </p>
            <p className="text-xs leading-6 text-muted-foreground">
              Diese Route rendert nur den Start-Overlay für den Updater.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2">
            {previewOrder.map((stage) => (
              <Button
                key={stage}
                asChild
                size="sm"
                variant={stage === activeStage ? "default" : "outline"}
              >
                <Link to={`/debug/desktop-update?stage=${stage}`}>{stage}</Link>
              </Button>
            ))}
          </div>

          <div className="mt-3 text-[11px] text-muted-foreground">
            Für einen sauberen Screenshot:
            {" "}
            <code>/debug/desktop-update?stage=checking&amp;controls=0</code>
          </div>
        </div>
      )}
    </div>
  );
}
